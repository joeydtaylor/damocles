// src/api/controllers/auth/oauth.controller.ts
import { Request, Response } from "express";
import crypto from "crypto";
import axios from "axios";
import { URLSearchParams } from "url";
import { OAuthService } from "../../services/oauth.service";
import { KeyService } from "../../services/key.service";
import { PrismaClient } from "@prisma/client";
import { setSessionAssertion } from "../../../utils/session-assertion";

const prisma = new PrismaClient();

/* ---------------- helpers ---------------- */
function base64ToBase64Url(b64: string): string {
  return b64.replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// Safe dynamic ESM import so ts-node doesn't turn it into require()
async function getJose() {
  // eslint-disable-next-line no-new-func
  return await new Function("return import('jose')")();
}

function jwksUrlFromIssuer(issuer: string) {
  const clean = issuer.replace(/\/+$/, "");
  if (/\/oauth2\/[^/]+$/.test(clean)) return `${clean}/v1/keys`;
  return `${clean}/oauth2/v1/keys`;
}

function sha256b64url(input: string): string {
  const raw = crypto.createHash("sha256").update(input).digest("base64");
  return base64ToBase64Url(raw);
}

function parseBasicAuth(req: Request): { client_id?: string; client_secret?: string } {
  const h = req.headers.authorization;
  if (!h || !h.startsWith("Basic ")) return {};
  try {
    const decoded = Buffer.from(h.slice(6), "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx < 0) return {};
    return {
      client_id: decoded.slice(0, idx),
      client_secret: decoded.slice(idx + 1),
    };
  } catch {
    return {};
  }
}

function jsonOrForm(req: Request): any {
  // Accept JSON or application/x-www-form-urlencoded
  return req.body || {};
}

function sendOauthError(res: Response, status: number, error: string, error_description?: string) {
  const body: any = { error };
  if (error_description) body.error_description = error_description;
  res.status(status).json(body);
}

/* ---------------- controller ---------------- */
export class OAuthController {
  private keys: KeyService;
  private svc: OAuthService;

  constructor(private security: Configuration.ISecurityConfiguration) {
    this.keys = new KeyService(security.oauth);
    this.svc = new OAuthService(security.oauth, this.keys);
  }

  // ---- OIDC Discovery (for YOUR issuer) ----
  discoveryDocument = async (_req: Request, res: Response): Promise<void> => {
    try {
      const base = this.security.oauth.issuer;
      res.json({
        issuer: base,
        authorization_endpoint: `${base}/api/auth/oauth/authorize`,
        token_endpoint: `${base}/api/auth/oauth/token`,
        jwks_uri: `${base}/api/auth/oauth/jwks.json`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "client_credentials", "refresh_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: [this.security.oauth.signingAlgorithm],
        scopes_supported: ["openid", "email", "profile", ...this.security.oauth.extraScopes],
        claims_supported: ["sub", "email", "email_verified", "name", "nonce"],
        token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
        userinfo_endpoint: `${base}/api/auth/oauth/userinfo`,
        introspection_endpoint: `${base}/api/auth/oauth/introspect`,
        revocation_endpoint: `${base}/api/auth/oauth/revoke`,
      });
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };

  // ---- JWKS (/.well-known and legacy path) ----
  jwksWellKnown = async (_req: Request, res: Response): Promise<void> => {
    try {
      const { jwk } = await this.keys.load();
      res.setHeader("Cache-Control", `public, max-age=${this.security.oauth.jwksCacheSeconds}`);
      res.json({ keys: [jwk] });
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };

  jwks = async (req: Request, res: Response): Promise<void> => {
    await this.jwksWellKnown(req, res);
  };

  // ---- Raw PEM public key download ----
  publicKeyPem = async (req: Request, res: Response): Promise<void> => {
    try {
      const pem = this.keys.readPublicPem();
      const sha = crypto.createHash("sha256").update(pem).digest("base64");
      const etag = `"${base64ToBase64Url(sha)}"`;

      if (req.headers["if-none-match"] === etag) {
        res.status(304).end();
        return;
      }

      res.setHeader("Content-Type", "application/x-pem-file; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="oauth-public.key.pem"');
      res.setHeader("ETag", etag);
      res.setHeader("Cache-Control", `public, max-age=${this.security.oauth.jwksCacheSeconds}`);
      res.send(pem);
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };

  // ---- /authorize (Authorization Code + PKCE, OIDC-ready) ----
  authorize = async (req: Request, res: Response): Promise<void> => {
    try {
      const {
        response_type,
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        state,
        scope,
        nonce,
      } = req.query as Record<string, string | undefined>;

      if (response_type !== "code") {
        res.status(400).send("unsupported_response_type");
        return;
      }
      if (!client_id || !redirect_uri || !code_challenge || !code_challenge_method) {
        res.status(400).send("invalid_request");
        return;
      }

      const userId =
        (req as any)?.user?.id ??
        (this.security.oauth.allowHeaderUser ? req.header("x-user-id") : undefined);

      if (!userId) {
        res.status(401).send("login_required");
        return;
      }

      const out = await this.svc.startAuthorizationCode({
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method: code_challenge_method as "S256" | "plain",
        userId: String(userId),
        scope,
        nonce,
      });

      if ("error" in out) {
        const status = out.error === "access_denied" ? 403 : 400;
        res.status(status).send(out.error);
        return;
      }

      const sep = redirect_uri.includes("?") ? "&" : "?";
      const stateParam = state ? `&state=${encodeURIComponent(state)}` : "";
      res.redirect(`${redirect_uri}${sep}code=${encodeURIComponent(out.code!)}${stateParam}`);
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };

  // ---- /token (client_credentials + authorization_code + refresh_token + optional id_token) ----
  token = async (req: Request, res: Response): Promise<void> => {
    try {
      // Accept JSON or form; support client_secret_basic
      const body = jsonOrForm(req);
      const basic = parseBasicAuth(req);

      const grant_type = body.grant_type as string | undefined;

      // If Basic present, prefer it over POST fields
      const client_id = basic.client_id ?? (body.client_id as string | undefined);
      const client_secret = basic.client_secret ?? (body.client_secret as string | undefined);

      const code = body.code as string | undefined;
      const code_verifier = body.code_verifier as string | undefined;
      const redirect_uri = body.redirect_uri as string | undefined;
      const scope = body.scope as string | undefined;
      const refresh_token = body.refresh_token as string | undefined;

      if (grant_type === "client_credentials") {
        if (!client_id || !(client_secret || basic.client_secret)) {
          sendOauthError(res, 400, "invalid_request");
          return;
        }
        const out = await this.svc.issueClientCredentialsToken({
          client_id,
          client_secret: client_secret!,
          scope,
        });
        if ("error" in out) {
          sendOauthError(res, 401, "invalid_client");
          return;
        }
        res.json({
          access_token: out.access_token,
          token_type: "Bearer",
          expires_in: this.security.oauth.accessTokenTtlSeconds,
          scope: out.scope,
        });
        return;
      }

      if (grant_type === "authorization_code") {
        if (!client_id || !code || !redirect_uri) {
          sendOauthError(res, 400, "invalid_request");
          return;
        }
        const out = await this.svc.exchangeAuthorizationCode({
          client_id,
          client_secret,
          code,
          code_verifier,
          redirect_uri,
          scope,
        });
        if ("error" in out) {
          const status = out.error === "invalid_client" ? 401 : 400;
          sendOauthError(res, status, out.error);
          return;
        }

        const bodyResp: any = {
          access_token: out.access_token,
          token_type: "Bearer",
          expires_in: this.security.oauth.accessTokenTtlSeconds,
          scope: out.scope,
        };
        if ((out as any).id_token) bodyResp.id_token = (out as any).id_token;
        if ((out as any).refresh_token) bodyResp.refresh_token = (out as any).refresh_token;

        res.json(bodyResp);
        return;
      }

      if (grant_type === "refresh_token") {
        if (!client_id || !refresh_token) {
          sendOauthError(res, 400, "invalid_request");
          return;
        }
        const out = await this.svc.refreshAccessToken({
          client_id,
          client_secret,
          refresh_token,
          scope,
        });
        if ("error" in out) {
          const status = out.error === "invalid_client" ? 401 : 400;
          res.status(status).json(out);
          return;
        }
        res.json({
          access_token: out.access_token,
          token_type: "Bearer",
          expires_in: this.security.oauth.accessTokenTtlSeconds,
          scope: out.scope,
          refresh_token: out.refresh_token,
        });
        return;
      }

      sendOauthError(res, 400, "unsupported_grant_type");
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };

  // ---- /userinfo (OIDC) ----
  userinfo = async (req: Request, res: Response): Promise<void> => {
    try {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith("Bearer ")) {
        res.status(401).json({ error: "invalid_token" });
        return;
      }
      const token = auth.slice(7);
      const out = await this.svc.getUserInfoFromAccessToken(token);
      if ("error" in out) {
        res.status(401).json(out);
        return;
      }
      res.json(out);
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };

  // ---- /introspect (RFC 7662) ----
  introspect = async (req: Request, res: Response): Promise<void> => {
    try {
      // Accept JSON or x-www-form-urlencoded
      const body = jsonOrForm(req);

      // Per RFC 7662 the token MUST be in the request body
      const token = (body?.token as string | undefined)?.trim();
      const tokenTypeHint = (body?.token_type_hint as string | undefined) || undefined;

      if (!token) {
        res.status(400).json({ active: false, error: "missing_token" });
        return;
      }

      // ---- Client Authentication (required) ----
      // Prefer HTTP Basic over POST fields when both are provided
      const basic = parseBasicAuth(req);
      const client_id =
        basic.client_id ?? (body.client_id as string | undefined)?.trim();
      const client_secret =
        basic.client_secret ?? (body.client_secret as string | undefined);

      if (!client_id) {
        // RFC 7662 allows the AS to require client auth; we do
        sendOauthError(res, 401, "invalid_client", "client authentication required");
        return;
      }

      // Look up the client
      const client = await prisma.oAuthClient.findUnique({
        where: { clientId: client_id },
      });

      if (!client) {
        // Do NOT leak whether the client exists; reply 401 per OAuth error semantics
        sendOauthError(res, 401, "invalid_client");
        return;
      }

      // If confidential, require and verify secret (bcrypt hash stored in DB)
      if (client.confidential) {
        if (!client_secret) {
          sendOauthError(res, 401, "invalid_client");
          return;
        }
        const ok = await import("bcrypt").then(({ default: bcrypt }) =>
          bcrypt.compare(client_secret, client.clientSecret)
        );
        if (!ok) {
          sendOauthError(res, 401, "invalid_client");
          return;
        }
      }

      // ---- Introspection proper ----
      // Your service should return RFC 7662-compatible structure:
      // { active: boolean, scope?: string, client_id?: string, aud?: string|string[], exp?: number, ... }
      const out = await this.svc.introspect(token);

      // If the AS chooses to signal errors, normalize to inactive when appropriate
      if (!out || (out as any).error) {
        res.status(200).json({ active: false });
        return;
      }

      // Hardening options (toggle on as needed)
      const requireSameClient =
        (this.security as any)?.oauth?.introspection?.requireSameClient ?? false;
      const requiredAudiences: string[] =
        (this.security as any)?.oauth?.introspection?.requiredAudiences ?? [];
      const requiredScopes: string[] =
        (this.security as any)?.oauth?.introspection?.requiredScopes ?? [];

      // (1) Enforce token was issued to this client_id (helps avoid token replay across RS)
      if (requireSameClient) {
        const tokenClientId = (out as any).client_id as string | undefined;
        if (tokenClientId && tokenClientId !== client.clientId) {
          // Don’t leak — standard practice is to return { active: false }
          res.status(200).json({ active: false });
          return;
        }
      }

      // (2) Enforce audience (if you set it on access tokens)
      if (requiredAudiences.length > 0) {
        const aud = (out as any).aud;
        const audList = Array.isArray(aud) ? aud : aud ? [aud] : [];
        const ok = requiredAudiences.every((a) => audList.includes(a));
        if (!ok) {
          res.status(200).json({ active: false });
          return;
        }
      }

      // (3) Enforce scopes (if your RS needs specific scopes)
      if (requiredScopes.length > 0) {
        const scopeStr = (out as any).scope as string | undefined; // space-delimited
        const scopes = scopeStr ? scopeStr.split(/\s+/).filter(Boolean) : [];
        const ok = requiredScopes.every((s) => scopes.includes(s));
        if (!ok) {
          res.status(200).json({ active: false });
          return;
        }
      }

      // Optionally honor token_type_hint (no-op here; included for completeness)
      void tokenTypeHint;

      // Success — return the full RFC 7662 response (do not add secrets)
      res.status(200).json(out);
      return;
    } catch {
      // Per spec, avoid leaking errors — 500 with OAuth body is acceptable
      sendOauthError(res, 500, "server_error");
      return;
    }
  };


  // ---- /revoke (RFC 7009) ----
  revoke = async (req: Request, res: Response): Promise<void> => {
    try {
      const body = jsonOrForm(req);
      const basic = parseBasicAuth(req);

      const client_id = basic.client_id ?? (body.client_id as string | undefined);
      const client_secret = basic.client_secret ?? (body.client_secret as string | undefined);
      const token = body.token as string | undefined;
      const token_type_hint = (body.token_type_hint as string | undefined) || undefined;

      if (!token || !client_id) {
        // Malformed request -> 400 (do not leak token validity)
        res.status(400).end();
        return;
      }

      const client = await prisma.oAuthClient.findUnique({ where: { clientId: client_id } });
      if (!client) {
        // Per spec, return 200 even if the client is unknown
        res.status(200).end();
        return;
      }
      if (client.confidential) {
        if (!client_secret) {
          res.status(401).end();
          return;
        }
        const ok = await import("bcrypt").then(({ default: bcrypt }) =>
          bcrypt.compare(client_secret, client.clientSecret)
        );
        if (!ok) {
          res.status(401).end();
          return;
        }
      }

      const now = new Date();

      // Try refresh token first (current or rotated previous)
      if (!token_type_hint || token_type_hint === "refresh_token") {
        const hash = sha256b64url(token);
        const row =
          (await prisma.oAuthToken.findFirst({
            where: { refreshTokenHash: hash, revokedAt: null },
          })) ||
          (await prisma.oAuthToken.findFirst({
            where: { refreshPrevTokenHash: hash },
          }));

        if (row && row.clientId === client.id) {
          if (row.refreshFamilyId) {
            await prisma.oAuthToken.updateMany({
              where: { refreshFamilyId: row.refreshFamilyId, revokedAt: null },
              data: { revokedAt: now },
            });
          } else {
            await prisma.oAuthToken.update({
              where: { id: row.id },
              data: { revokedAt: now },
            });
          }
          res.status(200).end();
          return;
        }
        // If not found, fall through and consider it as access token
      }

      if (!token_type_hint || token_type_hint === "access_token") {
        const row = await prisma.oAuthToken.findFirst({
          where: { accessToken: token, revokedAt: null },
        });
        if (row && row.clientId === client.id) {
          await prisma.oAuthToken.update({
            where: { id: row.id },
            data: { revokedAt: now },
          });
        }
        res.status(200).end();
        return;
      }

      // Unknown hint — still 200
      res.status(200).end();
    } catch {
      // Do not leak — revocation is idempotent
      res.status(200).end();
    }
  };

  // ===== Browser-friendly OIDC (Okta) Login Flow =====
  // ---- /oidc/login ----
  oidcLogin = async (req: any, res: any): Promise<void> => {
    try {
      const issuer = (process.env.OIDC_ISSUER_URL || "").replace(/\/+$/, "");
      const scopes = (process.env.OIDC_SCOPES || "openid profile email")
        .split(/[,\s]+/)
        .filter(Boolean)
        .join(" ");

      const state = crypto.randomBytes(16).toString("hex");
      const codeVerifier = base64ToBase64Url(crypto.randomBytes(32).toString("base64"));
      const codeChallenge = base64ToBase64Url(
        crypto.createHash("sha256").update(codeVerifier).digest("base64")
      );
      const nonce = crypto.randomBytes(16).toString("hex");

      req.session.oidcState = state;
      req.session.oidcVerifier = codeVerifier;
      req.session.oidcNonce = nonce;

      const authorizeUrl = new URL(`${issuer}/v1/authorize`);
      authorizeUrl.searchParams.set("client_id", process.env.OIDC_CLIENT_ID!);
      authorizeUrl.searchParams.set("redirect_uri", `${process.env.BASE_URL}/api/auth/oidc/callback`);
      authorizeUrl.searchParams.set("response_type", "code");
      authorizeUrl.searchParams.set("response_mode", "query");
      authorizeUrl.searchParams.set("scope", scopes);
      authorizeUrl.searchParams.set("state", state);
      authorizeUrl.searchParams.set("code_challenge", codeChallenge);
      authorizeUrl.searchParams.set("code_challenge_method", "S256");
      authorizeUrl.searchParams.set("nonce", nonce);

      res.redirect(authorizeUrl.toString());
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };

  // ---- /oidc/callback ----
  oidcCallback = async (req: any, res: any): Promise<void> => {
    try {
      const issuer = (process.env.OIDC_ISSUER_URL || "").replace(/\/+$/, "");
      const { code, state } = req.query as Record<string, string | undefined>;

      if (!code || !state || state !== req.session.oidcState) {
        res.status(400).send("Invalid state or missing code");
        return;
      }

      const tokenResp = await axios.post(
        `${issuer}/v1/token`,
        new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: `${process.env.BASE_URL}/api/auth/oidc/callback`,
          client_id: process.env.OIDC_CLIENT_ID!,
          ...(process.env.OIDC_CLIENT_SECRET ? { client_secret: process.env.OIDC_CLIENT_SECRET } : {}),
          code_verifier: req.session.oidcVerifier!,
        }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      const { id_token } = tokenResp.data;
      if (!id_token) {
        res.status(400).send("Missing id_token");
        return;
      }

      const jose = await getJose();
      const jwksUrl = process.env.OIDC_JWKS_URL || jwksUrlFromIssuer(issuer);
      const jwks = jose.createRemoteJWKSet(new URL(jwksUrl));
      const { payload } = await jose.jwtVerify(id_token, jwks, {
        issuer,
        audience: process.env.OIDC_CLIENT_ID,
      });

      if (payload.nonce !== req.session.oidcNonce) {
        res.status(400).send("Invalid nonce");
        return;
      }

      // Upsert user (adjust to your tenant selection logic as needed)
      let user = await prisma.user.findUnique({ where: { email: String(payload.email) } });
      if (!user) {
        const org = await prisma.organization.findFirstOrThrow({ where: { domain: "local" } });
        user = await prisma.user.create({
          data: {
            id: crypto.randomUUID(),
            email: String(payload.email),
            organizationId: org.id,
          },
        });
      }

      req.session.userId = user.id;

      // cleanup OIDC artifacts
      delete req.session.oidcState;
      delete req.session.oidcVerifier;
      delete req.session.oidcNonce;

      // Issue session assertion cookie (inherits SameSite/Secure)
      const userWithRoles = await prisma.user.findUnique({
        where: { id: user.id },
        include: { roles: true },
      });

      await setSessionAssertion(
        res,
        {
          id: user.id,
          organizationId: user.organizationId,
          roles: userWithRoles?.roles?.map((r: any) => r.name) ?? [],
          role: userWithRoles?.roles?.[0]?.name ?? "reader",
        },
        req.sessionID
      );

      res.redirect(process.env.FRONT_END_BASE_URL || "/");
    } catch {
      sendOauthError(res, 500, "server_error");
    }
  };
}
