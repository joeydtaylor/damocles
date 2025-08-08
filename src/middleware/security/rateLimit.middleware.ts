import rateLimit from "express-rate-limit";
import type { RequestHandler } from "express";

/* ---------- env helpers ---------- */
function envBool(name: string, def: boolean): boolean {
  const v = process.env[name]?.trim().toLowerCase();
  if (v === "true" || v === "1" || v === "yes") return true;
  if (v === "false" || v === "0" || v === "no") return false;
  return def;
}
function envInt(name: string, def: number): number {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v >= 0 ? v : def;
}

/**
 * Build a limiter with sane defaults for auth endpoints.
 * IMPORTANT: We call the library's ipKeyGenerator helper via the default export
 * to satisfy v7's IPv6 validation, while avoiding type shenanigans.
 */
function makeLimiter(opts: Partial<Parameters<typeof rateLimit>[0]> = {}): RequestHandler {
  const standardHeaders = envBool("RL_STANDARD_HEADERS", true);
  const legacyHeaders = envBool("RL_LEGACY_HEADERS", false);
  const trustProxy = envBool("RL_TRUST_PROXY", false);

  return rateLimit({
    standardHeaders,
    legacyHeaders,
    validate: { trustProxy },

    // TS note: use `any` to avoid the Request-vs-string type confusion you hit.
    keyGenerator: (req: any /* Request */, _res: any): string => {
      const ipPart: string =
        typeof (rateLimit as any).ipKeyGenerator === "function"
          ? (rateLimit as any).ipKeyGenerator(req)
          : (req.ip ?? "unknown");

      let cid = "";
      try {
        const fromBody = req?.body?.client_id as string | undefined;

        const auth = req?.headers?.authorization as string | undefined;
        let fromBasic: string | undefined;
        if (auth && auth.startsWith("Basic ")) {
          const dec = Buffer.from(auth.slice(6), "base64").toString("utf8");
          const idx = dec.indexOf(":");
          if (idx >= 0) fromBasic = dec.slice(0, idx);
        }
        cid = fromBody || fromBasic || "";
      } catch {
        /* ignore */
      }

      return cid ? `${ipPart}:${cid}` : ipPart;
    },

    message: { error: "rate_limited" },
    ...opts,
  });
}

/* ---------- Per-endpoint limits (override via env) ---------- */
const TOKEN_MAX = envInt("RL_TOKEN_MAX", 20);
const TOKEN_WINDOW = envInt("RL_TOKEN_WINDOW_MS", 60_000);

const REFRESH_MAX = envInt("RL_REFRESH_MAX", 15);
const REFRESH_WINDOW = envInt("RL_REFRESH_WINDOW_MS", 60_000);

const REVOKE_MAX = envInt("RL_REVOKE_MAX", 20);
const REVOKE_WINDOW = envInt("RL_REVOKE_WINDOW_MS", 60_000);

const INTROSPECT_MAX = envInt("RL_INTROSPECT_MAX", 60);
const INTROSPECT_WINDOW = envInt("RL_INTROSPECT_WINDOW_MS", 60_000);

const AUTHORIZE_MAX = envInt("RL_AUTHORIZE_MAX", 120);
const AUTHORIZE_WINDOW = envInt("RL_AUTHORIZE_WINDOW_MS", 60_000);

const USERINFO_MAX = envInt("RL_USERINFO_MAX", 120);
const USERINFO_WINDOW = envInt("RL_USERINFO_WINDOW_MS", 60_000);

export const tokenLimiter = makeLimiter({ max: TOKEN_MAX, windowMs: TOKEN_WINDOW });
export const refreshLimiter = makeLimiter({ max: REFRESH_MAX, windowMs: REFRESH_WINDOW });
export const revokeLimiter = makeLimiter({ max: REVOKE_MAX, windowMs: REVOKE_WINDOW });
export const introspectLimiter = makeLimiter({ max: INTROSPECT_MAX, windowMs: INTROSPECT_WINDOW });
export const authorizeLimiter = makeLimiter({ max: AUTHORIZE_MAX, windowMs: AUTHORIZE_WINDOW });
export const userinfoLimiter = makeLimiter({ max: USERINFO_MAX, windowMs: USERINFO_WINDOW });
