// app.ts
import express from "express";
import passport from "passport";
import cookieParser from "cookie-parser";
import session from "express-session";
import cors from "cors";
import helmet from "helmet";
import https from "https";
import http from "http";
import fs from "fs";
import Redis from "ioredis";
import RedisStore from "connect-redis";
import compression from "compression";
import "reflect-metadata";
import { globalConfiguration } from "./helpers/configuration.helper";
import { constants as tlsConsts } from "crypto";

/**
 * ENV knobs...
 */
function resolveTrustProxy(v: string | undefined) {
  if (v === undefined) return false;
  const s = v.trim().toLowerCase();
  if (s === "true") return true;
  if (s === "false") return false;
  const n = Number(s);
  if (!Number.isNaN(n)) return n;
  return s.includes(",") ? s.split(",").map(x => x.trim()) : s;
}

const loadProductionModules = (
  middleware: any,
  app: express.Express,
  condition: boolean
): void => {
  if (condition) app.use(middleware);
};

// ---- TLS / Security env knobs ----
const IS_PROD = process.env.NODE_ENV === "production";
const ENFORCE_TLS_REDIRECT =
  (process.env.ENFORCE_TLS_REDIRECT ?? (IS_PROD ? "true" : "false")) === "true";

const HSTS_MAX_AGE = parseInt(
  process.env.HSTS_MAX_AGE ?? `${60 * 60 * 24 * 365}`,
  10
);
const HSTS_INCLUDE_SUBDOMAINS =
  (process.env.HSTS_INCLUDE_SUBDOMAINS ?? "true") === "true";
const HSTS_PRELOAD = (process.env.HSTS_PRELOAD ?? "false") === "true";

const ENABLE_HTTP_REDIRECT = (process.env.ENABLE_HTTP_REDIRECT ?? "false") === "true";
const HTTP_REDIRECT_PORT = parseInt(process.env.HTTP_REDIRECT_PORT ?? "8080", 10);

const TLS_MIN_VERSION = (process.env.TLS_MIN_VERSION ?? "TLSv1.2") as
  | "TLSv1.2"
  | "TLSv1.3";
const TLS_CIPHERS = process.env.TLS_CIPHERS;

const REQUIRE_CLIENT_CERT = (process.env.REQUIRE_CLIENT_CERT ?? "false") === "true";
const CLIENT_CA_BUNDLE = process.env.TLS_CLIENT_CA_BUNDLE;

const main = async (): Promise<void> => {
  const app = express();

  app.set("trust proxy", resolveTrustProxy(process.env.TRUST_PROXY ?? (IS_PROD ? "true" : "false")));

  // 1. Passport setup
  await require("./middleware/authentication/passport.middleware")(passport, globalConfiguration);
  app.use(passport.initialize());

  // 2. Logging / Metrics
  await require("./middleware/logging/logger.middleware")(app, globalConfiguration);
  await require("./middleware/logging/prometheus.middleware")(app);

  // 2.5 Enforce HTTPS redirect early
  if (ENFORCE_TLS_REDIRECT) {
    const skip = new Set<string>(["/healthz", "/readyz", "/metrics"]);
    app.use((req, res, next) => {
      const isSecure =
        (req as any).secure || req.headers["x-forwarded-proto"] === "https";
      if (!isSecure && !skip.has(req.path)) {
        const host = req.headers.host;
        if (!host) {
          res.status(400).send("Bad Request");
          return;
        }
        const url = `https://${host}${req.originalUrl || req.url}`;
        res.redirect(307, url);
        return;
      }
      next();
    });
  }

  // 3. Compression & Helmet
  loadProductionModules(compression(), app, IS_PROD);
  app.use(
    helmet({
      hsts: {
        maxAge: HSTS_MAX_AGE,
        includeSubDomains: HSTS_INCLUDE_SUBDOMAINS,
        preload: HSTS_PRELOAD,
      },
    })
  );

  // 4. Basic middleware
  app.use(
    cors({
      origin: globalConfiguration.security.corsOrigin,
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Credentials",
      ],
      methods: ["GET", "PUT", "POST", "PATCH", "DELETE", "OPTIONS"],
      credentials: true,
    })
  );

  app.use(
    cookieParser(
      globalConfiguration.security.authentication.sessionStoreConfiguration.cookie.secret
    )
  );

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // 5. Redis session store
  const redisClient = new Redis(
    globalConfiguration.security.authentication.sessionStoreConfiguration.redisConnectionString
  );
  const redisStore = new (RedisStore as any)({
    client: redisClient,
    prefix: globalConfiguration.app.name,
  });

  app.use(
    session({
      store: redisStore,
      name: globalConfiguration.security.authentication.sessionStoreConfiguration.cookie.name,
      resave: false,
      saveUninitialized: false,
      secret:
        globalConfiguration.security.authentication.sessionStoreConfiguration.cookie.secret,
      cookie: {
        signed: true,
        secure: true,
        httpOnly: true,
        sameSite: globalConfiguration.security.authentication.sessionStoreConfiguration.cookie.sameSite,
        maxAge:
          globalConfiguration.security.authentication.sessionStoreConfiguration.cookie.maxAgeInHours *
          60 *
          60 *
          1000,
      },
    })
  );

  app.use(passport.session());

  // 6. Authentication Routes
  if (globalConfiguration.security.authentication.samlConfiguration.enabled) {
    await require("./api/routes/auth/saml.route")(app);
  }

  // OAuth2 / OIDC
  await require("./api/routes/auth/oauth.route")(app);
  await require("./api/routes/auth/oidc.route")(app);

  // 7. Other auth + core routes
  await require("./api/routes/auth/logout.route")(app);
  await require("./api/routes/auth/session.route")(app);
  await require("./api/routes/index.route")(app);

  // 8. Start HTTPS server (and optional HTTP→HTTPS redirect server)
  const httpsOptions: https.ServerOptions = {
    key: fs.readFileSync(globalConfiguration.security.serverSslPrivateKey),
    cert: fs.readFileSync(globalConfiguration.security.serverSslCertificate),
    minVersion: TLS_MIN_VERSION,
    ciphers: TLS_CIPHERS,
    honorCipherOrder: true,
    requestCert: REQUIRE_CLIENT_CERT,
    rejectUnauthorized: REQUIRE_CLIENT_CERT,
    ca:
      REQUIRE_CLIENT_CERT && CLIENT_CA_BUNDLE
        ? fs.readFileSync(CLIENT_CA_BUNDLE)
        : undefined,
    secureOptions:
      tlsConsts.SSL_OP_NO_COMPRESSION |
      tlsConsts.SSL_OP_NO_SSLv2 |
      tlsConsts.SSL_OP_NO_SSLv3,
  };

  const port = globalConfiguration.app.port;
  https.createServer(httpsOptions, app).listen(port, () => {
    console.log(`HTTPS server listening on port ${port}`);
  });

  if (ENABLE_HTTP_REDIRECT) {
    http
      .createServer((req, res) => {
        const host = req.headers.host;
        const url = host ? `https://${host}${req.url || "/"}` : undefined;
        if (!url) {
          res.statusCode = 400;
          res.end("Bad Request");
          return;
        }
        res.statusCode = 301;
        res.setHeader("Location", url);
        res.end(`Redirecting to ${url}`);
      })
      .listen(HTTP_REDIRECT_PORT, () => {
        console.log(`HTTP redirect server listening on ${HTTP_REDIRECT_PORT}`);
      });
  }
};

main().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
