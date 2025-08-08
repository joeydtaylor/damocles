import path from "path";
import fs from "fs";
import https from "https";
import { URL } from "url";
import { Writable } from "stream";
import express, { Request, Response } from "express";
import morgan from "morgan";
import { globalConfiguration } from "../../helpers/configuration";

const isProd = process.env.NODE_ENV === "production";
const logDir = path.join(__dirname, "../../../", globalConfiguration.app.logging.logDir);
const httpLogFileName = "http-access.log";
const rfs = require("rotating-file-stream");

/* ───────── Env (SIEM) ───────── */
const SIEM_ENABLED = /^true$/i.test(process.env.SIEM_ENABLED || "");
const SIEM_HTTP_URL = process.env.SIEM_HTTP_URL || "";
const SIEM_HTTP_AUTH_HEADER = process.env.SIEM_HTTP_AUTH_HEADER || "";
const SIEM_BATCH_SIZE = Math.max(1, Number(process.env.SIEM_BATCH_SIZE || 50));
const SIEM_FLUSH_MS = Math.max(250, Number(process.env.SIEM_FLUSH_MS || 2000));
const SIEM_TIMEOUT_MS = Math.max(1000, Number(process.env.SIEM_TIMEOUT_MS || 5000));
const SIEM_MAX_RETRIES = Math.max(0, Number(process.env.SIEM_MAX_RETRIES || 3));
const SIEM_DLQ_FILE = "siem-failover.log";

/* ───────── Redaction + Safe Serialize ───────── */
const SENSITIVE_KEY_REGEX =
  /(password|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|assertion|saml(request|response)?|authorization|client[_-]?secret)/i;
const SENSITIVE_QUERY_KEYS = [
  "code",
  "state",
  "id_token",
  "access_token",
  "refresh_token",
  "client_secret",
  "SAMLResponse",
  "SAMLRequest",
];
const MAX_VALUE_LEN = 256;

function maskValue(v: unknown): string {
  const s = String(v ?? "");
  if (!s) return "";
  return s.length > 12 ? `${s.slice(0, 3)}…[REDACTED]…${s.slice(-3)}` : "[REDACTED]";
}

function redactAuthHeader(val?: string | string[]) {
  const raw = Array.isArray(val) ? val.join(", ") : val || "";
  if (!raw) return undefined;
  const m = raw.match(/^Bearer\s+(.+)$/i);
  if (m) return "Bearer " + maskValue(m[1]);
  return "[REDACTED]";
}

function redactCookieHeader(val?: string | string[]) {
  const raw = Array.isArray(val) ? val.join("; ") : val || "";
  if (!raw) return undefined;
  return raw
    .split(/;\s*/)
    .map((pair) => {
      const [k, ...rest] = pair.split("=");
      const v = rest.join("=");
      if (!k) return pair;
      if (k === "s" || SENSITIVE_KEY_REGEX.test(k)) return `${k}=${maskValue(v)}`;
      return `${k}=${v}`;
    })
    .join("; ");
}

function deepRedact(input: any): any {
  if (input == null) return input;
  if (Array.isArray(input)) return input.map(deepRedact);

  if (typeof input === "object") {
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(input)) {
      if (SENSITIVE_KEY_REGEX.test(k)) {
        out[k] = "[REDACTED]";
      } else if (typeof v === "object" && v !== null) {
        out[k] = deepRedact(v);
      } else if (typeof v === "string" && v.length > MAX_VALUE_LEN) {
        out[k] = v.slice(0, MAX_VALUE_LEN) + "…";
      } else {
        out[k] = v;
      }
    }
    return out;
  }

  if (typeof input === "string" && input.length > MAX_VALUE_LEN) {
    return input.slice(0, MAX_VALUE_LEN) + "…";
  }
  return input;
}

function redactQuery(urlPath?: string): string | undefined {
  if (!urlPath) return undefined;
  const [p, q] = urlPath.split("?");
  if (!q) return urlPath;
  const qs = new URLSearchParams(q);
  for (const key of SENSITIVE_QUERY_KEYS) {
    if (qs.has(key)) qs.set(key, "[REDACTED]");
  }
  for (const k of Array.from(qs.keys())) {
    if (SENSITIVE_KEY_REGEX.test(k)) qs.set(k, "[REDACTED]");
  }
  const qsStr = qs.toString();
  return qsStr ? `${p}?${qsStr}` : p;
}

function safeStringify(obj: any): string {
  return JSON.stringify(
    obj,
    (_k, v) => {
      if (typeof v === "string" && v.length > 10_000) return v.slice(0, 10_000) + "…";
      return v;
    }
  );
}

/* ───────── SIEM HTTP sink (batched, buffered) ───────── */
class BatchedSiemSink extends Writable {
  private buf: string[] = [];
  private timer: NodeJS.Timeout | null = null;
  private failover: fs.WriteStream;
  private url?: URL;
  private hdrName?: string;
  private hdrValue?: string;

  constructor() {
    super({ decodeStrings: false });
    this.failover = rfs.createStream(SIEM_DLQ_FILE, {
      path: logDir,
      size: "10M",
      rotate: 10,
      teeToStdout: false,
    });

    if (SIEM_HTTP_URL) {
      this.url = new URL(SIEM_HTTP_URL);
    }
    if (SIEM_HTTP_AUTH_HEADER) {
      const idx = SIEM_HTTP_AUTH_HEADER.indexOf(":");
      if (idx > 0) {
        this.hdrName = SIEM_HTTP_AUTH_HEADER.slice(0, idx).trim();
        this.hdrValue = SIEM_HTTP_AUTH_HEADER.slice(idx + 1).trim();
      }
    }
  }

  _write(chunk: any, _enc: BufferEncoding, cb: (err?: Error | null) => void) {
    try {
      this.buf.push(String(chunk).trim());
      if (this.buf.length >= SIEM_BATCH_SIZE) {
        this.flush().finally(() => cb());
      } else {
        if (!this.timer) {
          this.timer = setTimeout(() => this.flush(), SIEM_FLUSH_MS);
          this.timer.unref?.();
        }
        cb();
      }
    } catch (e: any) {
      cb(e);
    }
  }

  async flush() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const batch = this.buf.splice(0, this.buf.length);
    if (!batch.length) return;

    if (!this.url) {
      for (const line of batch) this.failover.write(line + "\n");
      return;
    }

    const payload = Buffer.from(JSON.stringify({ logs: batch }), "utf8");

    let attempt = 0;
    while (true) {
      try {
        await this.post(payload);
        return;
      } catch (_err) {
        attempt++;
        if (attempt > SIEM_MAX_RETRIES) {
          for (const line of batch) this.failover.write(line + "\n");
          return;
        }
        await new Promise((r) => setTimeout(r, Math.min(1000 * attempt, 5000)));
      }
    }
  }

  private post(body: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.url) return reject(new Error("SIEM url missing"));
      const req = https.request(
        {
          method: "POST",
          protocol: this.url.protocol,
          hostname: this.url.hostname,
          port: this.url.port || 443,
          path: this.url.pathname + (this.url.search || ""),
          timeout: SIEM_TIMEOUT_MS,
          headers: {
            "content-type": "application/json",
            "content-length": String(body.length),
            ...(this.hdrName && this.hdrValue ? { [this.hdrName]: this.hdrValue } : {}),
          },
        },
        (res) => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            res.resume();
            resolve();
          } else {
            res.on("data", () => { });
            res.on("end", () => reject(new Error(`SIEM ${res.statusCode}`)));
          }
        }
      );
      req.on("error", reject);
      req.write(body);
      req.end();
    });
  }

  async _final(cb: (err?: Error | null) => void) {
    try {
      await this.flush();
      cb();
    } catch (e: any) {
      cb(e);
    }
  }
}

/* ───────── Morgan Setup ───────── */
module.exports = (app: express.Application, config: Configuration.ISchema) => {
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

  morgan.token("time", () => new Date().toISOString());
  morgan.token("remote-addr", (req: Request) => req.headers["x-forwarded-for"]?.toString() ?? req.socket.remoteAddress ?? undefined);
  morgan.token("remote-user", (req: Request) => (req as any).user?.username ?? undefined);
  morgan.token("remote-user-id", (req: Request) => (req as any).user?.id ?? undefined);
  morgan.token("remote-user-email", (req: Request) => (req as any).user?.email ?? undefined);
  morgan.token("remote-user-org", (req: Request) => (req as any).user?.organizationId ?? undefined);
  morgan.token("remote-user-role", (req: Request) => (req as any).user?.role ?? undefined);
  morgan.token("remote-user-roles", (req: Request) => (req as any).user?.roles?.join(",") ?? undefined);
  morgan.token("sessionID", (req: Request) => (isProd ? "[REDACTED]" : (req as any).session?.id ?? undefined));

  morgan.token("authorization", (req: Request) => redactAuthHeader(req.headers.authorization));
  morgan.token("cookie", (req: Request) => redactCookieHeader(req.headers.cookie));
  morgan.token("redacted-url", (req: Request) => redactQuery((req as any).originalUrl || (req as any).url));

  morgan.token("requestData", (req: Request) => {
    if (!(req as any).body || typeof (req as any).body !== "object") return undefined;
    if ((req as any).body.operationName === "IntrospectionQuery") return undefined;
    const p = (req as any).path || "";
    if (
      p.startsWith("/api/auth/oauth/token") ||
      p.startsWith("/api/auth/oauth/introspect") ||
      p.startsWith("/api/auth/oauth/authorize")
    ) {
      return "[REDACTED]";
    }
    return deepRedact((req as any).body);
  });

  const fileStream = (filePath: string) =>
    rfs.createStream(filePath, {
      path: logDir,
      size: `${config.app.logging.logMaxSizeInNumberMB}M`,
      rotate: config.app.logging.logMaxFilecount,
      interval: "1h",
      intervalBoundary: true,
      teeToStdout: true,
    });

  const skip = (req: Request) => {
    const p = (req as any).path || "";
    return (
      p === "/healthz" ||
      p === "/readyz" ||
      p.startsWith("/favicon") ||
      p.startsWith("/static/") ||
      p.startsWith("/assets/")
    );
  };

  const formatter = (tokens: any, req: Request, res: Response) =>
    safeStringify(
      deepRedact({
        time: tokens["time"](req, res),
        remoteAddress: tokens["remote-addr"](req, res),
        remoteUser: tokens["remote-user"](req, res),
        remoteUserId: tokens["remote-user-id"](req, res),
        remoteUserEmail: tokens["remote-user-email"](req, res),
        remoteUserOrg: tokens["remote-user-org"](req, res),
        remoteUserRole: tokens["remote-user-role"](req, res),
        remoteUserRoles: tokens["remote-user-roles"](req, res),
        session: tokens["sessionID"](req, res),
        httpMethod: tokens["method"](req, res),
        endpoint: tokens["redacted-url"](req, res) ?? tokens["url"](req, res),
        status: tokens["status"](req, res),
        requestHeaders: {
          authorization: tokens["authorization"](req, res),
          cookie: tokens["cookie"](req, res),
        },
        requestData: tokens["requestData"](req, res),
        responseTimeInMs: Number(tokens["response-time"](req, res)),
      })
    );

  app.use(morgan(formatter, { stream: fileStream(httpLogFileName), skip }));

  if (SIEM_ENABLED) {
    const siemSink = new BatchedSiemSink();
    app.use(morgan(formatter, { stream: siemSink as any, skip }));
  }
};
