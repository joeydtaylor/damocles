import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import Joi from "joi";

// Load .env, then overlay .env.<NODE_ENV> if present
const root = path.resolve(__dirname, "../../");
const baseEnv = path.join(root, ".env");
const envSpecific = path.join(root, `.env.${process.env.NODE_ENV || "development"}`);
if (fs.existsSync(baseEnv)) dotenv.config({ path: baseEnv });
if (fs.existsSync(envSpecific)) dotenv.config({ path: envSpecific });

// Schema with case-insensitive SameSite; coerce to lowercase
const sameSite = Joi.string().lowercase().valid("lax", "strict", "none");

const envVarsSchema = Joi.object({
  // Core
  PORT: Joi.number().default(3000),
  APP_NAME: Joi.string().required(),
  BASE_URL: Joi.string().uri().required(),
  FRONT_END_BASE_URL: Joi.string().uri().required(),

  // Logging
  LOG_DIRECTORY: Joi.string().required(),
  LOG_MAX_SIZE_IN_NUMBER_MB: Joi.number().required(),

  // TLS
  SERVER_SSL_CERTIFICATE: Joi.string().required(),
  SERVER_SSL_PRIVATE_KEY: Joi.string().required(),
  TLS_MIN_VERSION: Joi.string().valid("TLSv1.2", "TLSv1.3").default("TLSv1.2"),
  TLS_CIPHERS: Joi.string().allow("", null),
  REQUIRE_CLIENT_CERT: Joi.boolean().truthy("true").falsy("false").default(false),
  TLS_CLIENT_CA_BUNDLE: Joi.string().allow("", null),

  // Redis / Sessions
  REDIS_CONNECTION_STRING: Joi.string().required(),
  SESSION_COOKIE_SECRET: Joi.string().required(),
  SESSION_COOKIE_NAME: Joi.string().required(),
  SESSION_COOKIE_SAME_SITE: sameSite.required(),

  // App cookie (optional)
  APPLICATION_COOKIE_SECRET: Joi.string().allow("", null),
  APPLICATION_COOKIE_SAME_SITE: sameSite.allow("", null),

  // SAML (optional)
  SAML_SP_ENTITY_ID: Joi.string().allow("", null),
  SAML_METADATA_PATH: Joi.string().allow("", null),

  // Roles
  ADMIN_ROLE_NAME: Joi.string().required(),
  DEVELOPER_ROLE_NAME: Joi.string().required(),
  CONTRIBUTOR_ROLE_NAME: Joi.string().required(),
  READER_ROLE_NAME: Joi.string().required(),
  AUDITOR_ROLE_NAME: Joi.string().required(),
  SUPPORT_ROLE_NAME: Joi.string().required(),

  // OAuth2 / OIDC
  OAUTH_PRIVATE_KEY_PATH: Joi.string().required(),
  OAUTH_PUBLIC_KEY_PATH: Joi.string().required(),
  OAUTH_SIGNING_ALGORITHM: Joi.string().valid("RS256", "ES256").default("RS256"),
  OAUTH_ISSUER: Joi.string().required(),
  OAUTH_AUDIENCE: Joi.string().required(),
  OAUTH_ACCESS_TTL_SECONDS: Joi.number().integer().min(60).default(3600),
  OAUTH_ENFORCE_S256_PKCE: Joi.boolean().truthy("true").falsy("false").default(true),
  OAUTH_ALLOW_HEADER_USER: Joi.boolean().truthy("true").falsy("false").default(false),
  OAUTH_JWKS_CACHE_SECONDS: Joi.number().integer().min(0).default(3600),
  OAUTH_REFRESH_TTL_SECONDS: Joi.number().integer().min(0).default(0),
  OAUTH_EXTRA_SCOPES: Joi.string().allow("", null),

  // Rate limiting (per endpoint)
  RL_AUTHORIZE_WINDOW_MS: Joi.number().integer().min(0).default(60000),
  RL_AUTHORIZE_MAX: Joi.number().integer().min(1).default(30),
  RL_TOKEN_WINDOW_MS: Joi.number().integer().min(0).default(60000),
  RL_TOKEN_MAX: Joi.number().integer().min(1).default(60),
  RL_REFRESH_WINDOW_MS: Joi.number().integer().min(0).default(60000),
  RL_REFRESH_MAX: Joi.number().integer().min(1).default(10),
  RL_USERINFO_WINDOW_MS: Joi.number().integer().min(0).default(60000),
  RL_USERINFO_MAX: Joi.number().integer().min(1).default(120),
  RL_INTROSPECT_WINDOW_MS: Joi.number().integer().min(0).default(60000),
  RL_INTROSPECT_MAX: Joi.number().integer().min(1).default(30),
  RL_REVOKE_WINDOW_MS: Joi.number().integer().min(0).default(60000),
  RL_REVOKE_MAX: Joi.number().integer().min(1).default(20),
  RL_TRUST_PROXY: Joi.boolean().truthy("true").falsy("false").default(false),
  RL_STANDARD_HEADERS: Joi.boolean().truthy("true").falsy("false").default(true),
  RL_LEGACY_HEADERS: Joi.boolean().truthy("true").falsy("false").default(false),

  // SIEM
  SIEM_ENABLED: Joi.boolean().truthy("true").falsy("false").default(false),
  SIEM_HTTP_URL: Joi.string().uri().allow(""),
  SIEM_HTTP_AUTH_HEADER: Joi.string().allow(""),
  SIEM_BATCH_SIZE: Joi.number().integer().min(1).default(50),
  SIEM_FLUSH_MS: Joi.number().integer().min(1).default(2000),
  SIEM_TIMEOUT_MS: Joi.number().integer().min(1).default(5000),
  SIEM_MAX_RETRIES: Joi.number().integer().min(0).default(3),

  // Misc TLS/HTTP
  TRUST_PROXY: Joi.alternatives().try(Joi.boolean(), Joi.string(), Joi.number()).default(false),
  ENFORCE_TLS_REDIRECT: Joi.boolean().truthy("true").falsy("false").default(true),
  HSTS_MAX_AGE: Joi.number().integer().min(0).default(31536000),
  HSTS_INCLUDE_SUBDOMAINS: Joi.boolean().truthy("true").falsy("false").default(true),
  HSTS_PRELOAD: Joi.boolean().truthy("true").falsy("false").default(false),
  ENABLE_HTTP_REDIRECT: Joi.boolean().truthy("true").falsy("false").default(false),
  HTTP_REDIRECT_PORT: Joi.number().integer().min(1).default(8080),
})
  .unknown()
  .prefs({ convert: true })
  .required();

const { error, value: env } = envVarsSchema.validate(process.env);
if (error) throw new Error(`Config validation error: ${error.message}`);

export const config: Configuration.ISchema = {
  app: {
    name: env.APP_NAME,
    port: env.PORT,
    logging: {
      logDir: env.LOG_DIRECTORY,
      logRetentionInDays: 1,
      logMaxSizeInNumberMB: env.LOG_MAX_SIZE_IN_NUMBER_MB,
      logMaxFilecount: 4,
    },
    baseUrl: env.BASE_URL,
    frontEndBaseUrl: env.FRONT_END_BASE_URL,
  },
  security: {
    corsOrigin: [],
    serverSslCertificate: env.SERVER_SSL_CERTIFICATE,
    serverSslPrivateKey: env.SERVER_SSL_PRIVATE_KEY,
    authentication: {
      samlConfiguration: {
        enabled: Boolean(env.SAML_SP_ENTITY_ID && env.SAML_METADATA_PATH),
        strategy: "saml",
        spPrivateKey: "",
        spPublicCertificate: "",
        path: "/api/auth/saml/consume",
        issuer: env.SAML_SP_ENTITY_ID || "",
        samlMetadataPath: env.SAML_METADATA_PATH || "",
      },
      sessionStoreConfiguration: {
        redisConnectionString: env.REDIS_CONNECTION_STRING,
        cookie: {
          secret: env.SESSION_COOKIE_SECRET,
          sameSite: env.SESSION_COOKIE_SAME_SITE as any,
          secure: true,
          httpOnly: true,
          name: env.SESSION_COOKIE_NAME,
          signed: true,
          maxAgeInHours: 24,
        },
        resave: false,
        saveUninitialized: false,
      },
      applicationCookieConfiguration: {
        secret: env.APPLICATION_COOKIE_SECRET || "",
        signed: Boolean(env.APPLICATION_COOKIE_SECRET),
        secure: true,
        httpOnly: false,
        sameSite: (env.APPLICATION_COOKIE_SAME_SITE as any) || "lax",
      },
    },
    authorization: {
      roles: {
        admin: { name: env.ADMIN_ROLE_NAME },
        developer: { name: env.DEVELOPER_ROLE_NAME },
        contributor: { name: env.CONTRIBUTOR_ROLE_NAME },
        reader: { name: env.READER_ROLE_NAME },
        auditor: { name: env.AUDITOR_ROLE_NAME },
        support: { name: env.SUPPORT_ROLE_NAME },
      },
    },
    oauth: {
      privateKeyPath: env.OAUTH_PRIVATE_KEY_PATH,
      publicKeyPath: env.OAUTH_PUBLIC_KEY_PATH,
      signingAlgorithm: env.OAUTH_SIGNING_ALGORITHM,
      issuer: env.OAUTH_ISSUER,
      audience: env.OAUTH_AUDIENCE,
      accessTokenTtlSeconds: env.OAUTH_ACCESS_TTL_SECONDS,
      enforceS256Pkce: env.OAUTH_ENFORCE_S256_PKCE,
      allowHeaderUser: env.OAUTH_ALLOW_HEADER_USER,
      jwksCacheSeconds: env.OAUTH_JWKS_CACHE_SECONDS,
      extraScopes: env.OAUTH_EXTRA_SCOPES
        ? env.OAUTH_EXTRA_SCOPES.split(",").map((s: string) => s.trim()).filter(Boolean)
        : [],
      refreshTokenTtlSeconds: env.OAUTH_REFRESH_TTL_SECONDS,
    },
  },
};

export default config;
