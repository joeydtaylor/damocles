import bcrypt from "bcrypt";
import { PrismaClient } from "@prisma/client";
import { randomUUID, createHash, randomBytes } from "crypto";
import type { JWTPayload } from "jose";
import { KeyService } from "./key.service";

const prisma = new PrismaClient();

/* ---------------- helpers ---------------- */
const b64url = (buf: Buffer) =>
  buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

const isValidCodeVerifier = (s: string) =>
  typeof s === "string" && s.length >= 43 && s.length <= 128 && /^[A-Za-z0-9\-._~]+$/.test(s);

const isValidB64Url = (s: string) => /^[A-Za-z0-9\-_]+$/.test(s);

const enforceRedirectUri = (candidate: string, allowed?: string[] | null) =>
  Array.isArray(allowed) && allowed.length > 0 && allowed.some((u) => candidate === u);

const intersectScopes = (requested: string[], allowed: string[]) =>
  requested.length ? requested.filter((s) => allowed.includes(s)) : allowed;

const isSubset = (subset: string[], superset: string[]) =>
  subset.every((s) => superset.includes(s));

const sha256b64url = (v: string) => b64url(createHash("sha256").update(v).digest());

async function getJose() {
  // eslint-disable-next-line no-new-func
  return await new Function("return import('jose')")();
}

/* ---------------- types ---------------- */
type StartAuthorizationCodeInput = {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: "S256" | "plain";
  userId: string;
  scope?: string;
  nonce?: string;
};

type StartAuthorizationCodeOutput =
  | { code: string }
  | { error: "invalid_request" | "invalid_client" | "access_denied" };

type ClientCredentialsInput = {
  client_id: string;
  client_secret: string;
  scope?: string;
};

type ClientCredentialsOutput =
  | { access_token: string; scope: string }
  | { error: "invalid_client" | "invalid_request" };

type ExchangeAuthorizationCodeInput = {
  client_id: string;
  client_secret?: string;
  code: string;
  code_verifier?: string;
  redirect_uri: string;
  scope?: string;
};

type ExchangeAuthorizationCodeOutput =
  | { access_token: string; scope: string; id_token?: string; refresh_token?: string }
  | { error: "invalid_request" | "invalid_client" | "invalid_grant" };

type RefreshAccessTokenInput = {
  client_id: string;
  client_secret?: string;
  refresh_token: string;
  scope?: string; // optional scope-down
};

type RefreshAccessTokenOutput =
  | { access_token: string; scope: string; refresh_token: string }
  | { error: "invalid_request" | "invalid_client" | "invalid_grant"; error_description?: string };

/* ---------------- service ---------------- */
export class OAuthService {
  constructor(
    private oauthCfg: Configuration.ISecurityConfiguration["oauth"],
    private keys: KeyService
  ) {}

  /* ---- /authorize ---- */
  public async startAuthorizationCode(
    input: StartAuthorizationCodeInput
  ): Promise<StartAuthorizationCodeOutput> {
    const {
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      userId,
      scope,
      nonce,
    } = input;

    if (!client_id || !redirect_uri || !code_challenge || !code_challenge_method) {
      return { error: "invalid_request" };
    }

    if (this.oauthCfg.enforceS256Pkce && code_challenge_method !== "S256") {
      return { error: "invalid_request" };
    }
    if (code_challenge_method !== "S256" && code_challenge_method !== "plain") {
      return { error: "invalid_request" };
    }
    if (code_challenge_method === "plain" && !isValidCodeVerifier(code_challenge)) {
      return { error: "invalid_request" };
    }
    if (code_challenge_method === "S256" && !isValidB64Url(code_challenge)) {
      return { error: "invalid_request" };
    }

    const client = await prisma.oAuthClient.findUnique({ where: { clientId: client_id } });
    if (!client) return { error: "invalid_client" };

    if (!enforceRedirectUri(redirect_uri, client.redirectUris)) {
      return { error: "invalid_request" };
    }

    const user = await prisma.user.findUnique({ where: { id: String(userId) } });
    if (!user || user.organizationId !== client.organizationId) {
      return { error: "access_denied" };
    }

    const requested = (scope ?? "").trim().split(/\s+/).filter(Boolean);
    const granted = intersectScopes(requested, client.scopes);

    const code = randomUUID();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await prisma.authorizationCode.create({
      data: {
        id: code,
        clientId: client.id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        method: code_challenge_method,
        expiresAt,
        userId: user.id,
        scope: granted,
        nonce: nonce ?? null,
      },
    });

    return { code };
  }

  /* ---- /token: client_credentials ---- */
  public async issueClientCredentialsToken(
    input: ClientCredentialsInput
  ): Promise<ClientCredentialsOutput> {
    const { client_id, client_secret, scope } = input;

    if (!client_id || !client_secret) return { error: "invalid_request" };

    const client = await prisma.oAuthClient.findUnique({
      where: { clientId: client_id },
      include: { organization: true },
    });
    if (!client) return { error: "invalid_client" };

    const ok = await bcrypt.compare(client_secret, client.clientSecret);
    if (!ok) return { error: "invalid_client" };

    const requested = (scope ?? "").trim().split(/\s+/).filter(Boolean);
    const granted = intersectScopes(requested, client.scopes);

    const jose = await getJose();
    const { privateKey, kid } = await this.keys.load();

    const now = Math.floor(Date.now() / 1000);
    // Ensure token uniqueness even under concurrent requests in the same second
    const accessToken = await new jose.SignJWT({
      jti: randomUUID(),
      sub: client.clientId,
      cid: client.clientId,
      org: client.organizationId,
      scope: granted.join(" "),
    })
      .setProtectedHeader({ alg: this.oauthCfg.signingAlgorithm, kid, typ: "JWT" })
      .setIssuer(this.oauthCfg.issuer)
      .setAudience(this.oauthCfg.audience)
      .setIssuedAt(now)
      .setExpirationTime(now + this.oauthCfg.accessTokenTtlSeconds)
      .sign(privateKey);

    // Idempotent write — if somehow the same token reappears, avoid a 500
    await prisma.oAuthToken.upsert({
      where: { accessToken },
      update: {},
      create: {
        id: randomUUID(),
        accessToken,
        scope: granted,
        expiresAt: new Date((now + this.oauthCfg.accessTokenTtlSeconds) * 1000),
        client: { connect: { id: client.id } },
        organization: { connect: { id: client.organizationId } },
      },
    });

    return { access_token: accessToken, scope: granted.join(" ") };
  }

  /* ---- /token: authorization_code (+ PKCE, optional OIDC id_token) ---- */
  public async exchangeAuthorizationCode(
    input: ExchangeAuthorizationCodeInput
  ): Promise<ExchangeAuthorizationCodeOutput> {
    const { client_id, client_secret, code, code_verifier, redirect_uri, scope } = input;

    if (!client_id || !code || !redirect_uri) return { error: "invalid_request" };

    const client = await prisma.oAuthClient.findUnique({
      where: { clientId: client_id },
      include: { organization: true },
    });
    if (!client) return { error: "invalid_grant" };

    // confidential clients must authenticate
    if (client.confidential) {
      if (!client_secret) return { error: "invalid_client" };
      const ok = await bcrypt.compare(client_secret, client.clientSecret);
      if (!ok) return { error: "invalid_client" };
    }

    try {
      const jose = await getJose();
      const { privateKey, kid } = await this.keys.load();

      const result = await prisma.$transaction(async (tx) => {
        const authCode = await tx.authorizationCode.findUnique({ where: { id: code } });
        if (!authCode) return { err: "invalid_grant" as const };

        // basic checks
        if (new Date(authCode.expiresAt) < new Date()) return { err: "invalid_grant" as const };
        if (authCode.redirectUri !== redirect_uri) return { err: "invalid_grant" as const };
        if (authCode.clientId !== client.id) return { err: "invalid_grant" as const };

        // PKCE verify
        if (authCode.method === "S256") {
          if (!code_verifier || !isValidCodeVerifier(code_verifier)) return { err: "invalid_grant" as const };
          const expected = b64url(createHash("sha256").update(code_verifier).digest());
          if (expected !== authCode.codeChallenge) return { err: "invalid_grant" as const };
        } else if (authCode.method === "plain") {
          if (!code_verifier || code_verifier !== authCode.codeChallenge) return { err: "invalid_grant" as const };
        } else {
          return { err: "invalid_grant" as const };
        }

        // One-time use
        await tx.authorizationCode.delete({ where: { id: authCode.id } });

        // Scopes
        const requestedNow = (scope ?? "").trim().split(/\s+/).filter(Boolean);
        const grantedArr = (authCode.scope?.length
          ? authCode.scope
          : intersectScopes(requestedNow, client.scopes)) as string[];
        const granted = grantedArr.join(" ");

        const now = Math.floor(Date.now() / 1000);
        const accessJwt = await new jose.SignJWT({
          jti: randomUUID(),
          sub: authCode.userId!,
          uid: authCode.userId!,
          org: client.organizationId,
          scope: granted,
          cid: client.clientId,
        })
          .setProtectedHeader({ alg: this.oauthCfg.signingAlgorithm, kid, typ: "JWT" })
          .setIssuer(this.oauthCfg.issuer)
          .setAudience(this.oauthCfg.audience)
          .setIssuedAt(now)
          .setExpirationTime(now + this.oauthCfg.accessTokenTtlSeconds)
          .sign(privateKey);

        // Mint refresh token (plaintext for response, hash in DB)
        const refreshPlain = b64url(randomBytes(32));
        const refreshHash = sha256b64url(refreshPlain);
        const familyId = randomUUID();
        const refreshExpires = new Date(Date.now() + this.oauthCfg.refreshTokenTtlSeconds * 1000);

        await tx.oAuthToken.create({
          data: {
            id: randomUUID(),
            accessToken: accessJwt,
            refreshTokenHash: refreshHash,
            refreshPrevTokenHash: null,
            refreshFamilyId: familyId,
            refreshExpiresAt: refreshExpires,
            scope: grantedArr,
            expiresAt: new Date((now + this.oauthCfg.accessTokenTtlSeconds) * 1000),
            client: { connect: { id: client.id } },
            user: authCode.userId ? { connect: { id: authCode.userId } } : undefined,
            organization: { connect: { id: client.organizationId } },
          },
        });

        // Optional OIDC id_token
        let idToken: string | undefined;
        if (grantedArr.includes("openid")) {
          const payload: JWTPayload & { nonce?: string } = {
            iss: this.oauthCfg.issuer,
            aud: client.clientId,
            sub: authCode.userId || "",
            iat: now,
            exp: now + this.oauthCfg.accessTokenTtlSeconds,
          };
          if (authCode.nonce) payload.nonce = authCode.nonce;

          idToken = await new jose.SignJWT(payload as any)
            .setProtectedHeader({ alg: this.oauthCfg.signingAlgorithm, kid, typ: "JWT" })
            .sign(privateKey);
        }

        return { accessJwt, granted, idToken, refreshPlain };
      });

      // If any of the checks returned an error sentinel, map it
      if ((result as any)?.err) return { error: "invalid_grant" };

      const ok = result as { accessJwt: string; granted: string; idToken?: string; refreshPlain: string };
      return {
        access_token: ok.accessJwt,
        scope: ok.granted,
        id_token: ok.idToken,
        refresh_token: ok.refreshPlain,
      };
    } catch {
      // Any unexpected DB or signing error -> generic invalid_grant
      return { error: "invalid_grant" };
    }
  }

  /* ---- /token: refresh_token (rotation + reuse detection) ---- */
  public async refreshAccessToken(
    input: RefreshAccessTokenInput
  ): Promise<RefreshAccessTokenOutput> {
    const { client_id, client_secret, refresh_token, scope } = input;

    if (!client_id || !refresh_token) {
      return { error: "invalid_request", error_description: "Missing client_id or refresh_token" };
    }

    const client = await prisma.oAuthClient.findUnique({
      where: { clientId: client_id },
      include: { organization: true },
    });
    if (!client) return { error: "invalid_client" };

    if (client.confidential) {
      if (!client_secret) return { error: "invalid_client", error_description: "Missing client_secret" };
      const ok = await bcrypt.compare(client_secret, client.clientSecret);
      if (!ok) return { error: "invalid_client" };
    }

    const { privateKey, kid } = await this.keys.load();

    const hash = sha256b64url(refresh_token);

    // 1) Look for a current token with this refresh hash
    const tokenRow = await prisma.oAuthToken.findFirst({
      where: { refreshTokenHash: hash, revokedAt: null },
    });

    // 2) If not found, check if this matches a *previous* (rotated) hash => token reuse
    if (!tokenRow) {
      const reused = await prisma.oAuthToken.findFirst({
        where: { refreshPrevTokenHash: hash },
      });
      if (reused && reused.refreshFamilyId) {
        // Revoke entire family
        await prisma.oAuthToken.updateMany({
          where: { refreshFamilyId: reused.refreshFamilyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }
      return { error: "invalid_grant", error_description: "Invalid or reused refresh_token" };
    }

    // 3) Expiry check
    if (tokenRow.refreshExpiresAt && tokenRow.refreshExpiresAt < new Date()) {
      return { error: "invalid_grant", error_description: "Refresh token expired" };
    }

    // 4) Optional scope-down
    const currentScopes = tokenRow.scope ?? [];
    const requested = (scope ?? "").trim().split(/\s+/).filter(Boolean);
    const newScopes = requested.length ? requested : currentScopes;
    if (!isSubset(newScopes, currentScopes)) {
      return { error: "invalid_grant", error_description: "Requested scope exceeds original grant" };
    }

    // 5) Rotate: mint new refresh token + access token
    const now = Math.floor(Date.now() / 1000);
    const accessJwt = await new (await getJose()).SignJWT({
      jti: randomUUID(),
      sub: (tokenRow as any).userId ?? client.clientId,
      uid: (tokenRow as any).userId ?? undefined,
      org: client.organizationId,
      scope: newScopes.join(" "),
      cid: client.clientId,
    })
      .setProtectedHeader({ alg: this.oauthCfg.signingAlgorithm, kid, typ: "JWT" })
      .setIssuer(this.oauthCfg.issuer)
      .setAudience(this.oauthCfg.audience)
      .setIssuedAt(now)
      .setExpirationTime(now + this.oauthCfg.accessTokenTtlSeconds)
      .sign(privateKey);

    const newRefreshPlain = b64url(randomBytes(32));
    const newRefreshHash = sha256b64url(newRefreshPlain);
    const refreshExpires = new Date(Date.now() + this.oauthCfg.refreshTokenTtlSeconds * 1000);

    // Rotate in-place: remember previous hash for reuse detection
    await prisma.oAuthToken.update({
      where: { id: tokenRow.id },
      data: {
        accessToken: accessJwt,
        scope: newScopes,
        expiresAt: new Date((now + this.oauthCfg.accessTokenTtlSeconds) * 1000),
        refreshPrevTokenHash: tokenRow.refreshTokenHash,
        refreshTokenHash: newRefreshHash,
        refreshExpiresAt: refreshExpires,
      },
    });

    return {
      access_token: accessJwt,
      scope: newScopes.join(" "),
      refresh_token: newRefreshPlain,
    };
  }

  /* ---- /introspect ---- */
  public async introspect(token: string): Promise<any> {
    const jose = await getJose();
    const { publicKey } = await this.keys.load();

    try {
      const { payload, protectedHeader } = await jose.jwtVerify(token, publicKey, {
        algorithms: [this.oauthCfg.signingAlgorithm],
        audience: this.oauthCfg.audience,
        issuer: this.oauthCfg.issuer,
      });
      if (protectedHeader.alg !== this.oauthCfg.signingAlgorithm) {
        return { active: false };
      }

      return {
        active: true,
        iss: payload.iss,
        aud: payload.aud,
        sub: payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        scope: (payload as any).scope ?? "",
        org: (payload as any).org,
        cid: (payload as any).cid,
        uid: (payload as any).uid,
      };
    } catch {
      return { active: false };
    }
  }

  public async getUserInfoFromAccessToken(token: string): Promise<any> {
    const jose = await getJose();
    const { publicKey } = await this.keys.load();

    try {
      const { payload, protectedHeader } = await jose.jwtVerify(token, publicKey, {
        algorithms: [this.oauthCfg.signingAlgorithm],
        audience: this.oauthCfg.audience,
        issuer: this.oauthCfg.issuer,
      });

      if (protectedHeader.alg !== this.oauthCfg.signingAlgorithm) {
        return { error: "invalid_token" };
      }

      // Pull scopes off the token
      const scopeStr = String((payload as any).scope || "");
      const scopes = scopeStr.split(/\s+/).filter(Boolean);

      // Determine if this is a user token vs client_credentials token
      const uid = (payload as any).uid ?? null; // set for authorization_code

      if (!uid) {
        return {
          error: "insufficient_scope",
          error_description:
            "userinfo requires a user access token (authorization_code), not client_credentials",
        };
      }

      // Fetch user only if we need fields for granted scopes
      const needsEmail = scopes.includes("email");
      const needsProfile = scopes.includes("profile");

      let user: { email: string | null } | null = null;
      if (needsEmail || needsProfile) {
        user = await prisma.user.findUnique({ where: { id: String(uid) } });
      }

      // Build OIDC-compliant response with only requested claims
      const out: Record<string, any> = { sub: String(uid) };

      if (needsEmail) {
        out.email = user?.email ?? null;
        out.email_verified = user?.email ? true : null;
      }

      return out;
    } catch {
      return { error: "invalid_token" };
    }
  }
}
