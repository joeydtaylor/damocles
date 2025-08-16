import type { Response } from "express";
import { globalConfiguration } from "../helpers/configuration.helper";
import { KeyService } from "../api/services/key.service";

// Lazy ESM import for jose (works under ts-node CJS)
let _jose: any | null = null;
async function getJose() {
  if (_jose) return _jose;
  // eslint-disable-next-line no-new-func
  _jose = await new Function("return import('jose')")();
  return _jose;
}

type UserCtx = {
  id: string;
  organizationId: string;
  roles: string[];
  role?: string;
};

const COOKIE_NAME = "assert"; // keep separate from session cookie

/**
 * Signs a short-lived assertion JWT bound to the session and sets it as an HttpOnly cookie.
 * Safe against late writes: skips cookie if headers already went out.
 */
export async function setSessionAssertion(
  res: Response,
  user: UserCtx,
  sessionId?: string,
  ttlSeconds?: number
): Promise<void> {
  const security = globalConfiguration.security;

  const sessCfg = security.authentication.sessionStoreConfiguration.cookie;
  const appCookieCfg = security.authentication.applicationCookieConfiguration;

  // SameSite precedence: app cookie > session cookie
  const sameSite: any = (appCookieCfg.sameSite as any) ?? (sessCfg.sameSite as any);

  // TTL: explicit arg > session cookie maxAge > 30 minutes fallback
  const effectiveTtlSeconds =
    ttlSeconds ??
    (typeof sessCfg.maxAgeInHours === "number" ? sessCfg.maxAgeInHours * 3600 : 1800);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.max(60, effectiveTtlSeconds); // enforce minimum 60s

  // Use the same key material/algorithm as OAuth tokens to keep one trust root
  const ks = new KeyService(security.oauth);
  const jose = await getJose();
  const { privateKey, kid } = await ks.load();

  const payload = {
    ver: 1,
    sid: sessionId || "",
    uid: user.id,
    org: user.organizationId,
    roles: Array.isArray(user.roles) ? user.roles : [],
    role: user.role || undefined,
    iat: now,
    exp,
  };

  const jwt = await new jose.SignJWT(payload as any)
    .setProtectedHeader({ alg: security.oauth.signingAlgorithm, kid, typ: "JWT" })
    .setIssuer(security.oauth.issuer)
    .setAudience("session-assertion")
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(privateKey);

  const cookieOpts = {
    httpOnly: true,
    secure: true,
    sameSite,
    signed: appCookieCfg.signed,
    path: "/",
    maxAge: (exp - now) * 1000,
  } as const;

  // Guard against late header writes to avoid ERR_HTTP_HEADERS_SENT
  if ((res as any).headersSent) return;
  try {
    res.cookie(COOKIE_NAME, jwt, cookieOpts);
  } catch {
    // non-fatal; skip cookie if already committed by another layer
  }
}

/**
 * Clears the assertion cookie (safe if headers already sent).
 */
export function clearSessionAssertion(res: Response) {
  const security = globalConfiguration.security;
  const sessCfg = security.authentication.sessionStoreConfiguration.cookie;
  const appCookieCfg = security.authentication.applicationCookieConfiguration;
  const sameSite: any = (appCookieCfg.sameSite as any) ?? (sessCfg.sameSite as any);

  if ((res as any).headersSent) return;
  try {
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: true,
      sameSite,
      signed: appCookieCfg.signed,
      path: "/",
    });
  } catch {
    // non-fatal
  }
}
