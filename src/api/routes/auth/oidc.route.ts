// src/api/routes/auth/oidc.route.ts
import express from "express";
import { OAuthController } from "../../controllers/auth/oauth.controller";
import { globalConfiguration } from "../../../helpers/configuration.helper";
import {
  revokeLimiter,
  userinfoLimiter,
  authorizeLimiter,
} from "../../../middleware/security/rateLimit.middleware";
import { noStore } from "../../../middleware/security/noStore.middleware";

module.exports = (app: express.Application) => {
  const oidc = new OAuthController(globalConfiguration.security);

  // Discovery & JWKS (can be cached by clients/CDNs)
  app.get("/.well-known/openid-configuration", oidc.discoveryDocument.bind(oidc));
  app.get("/.well-known/jwks.json", oidc.jwksWellKnown.bind(oidc));

  // ----- OIDC-specific endpoints -----
  app.get("/api/auth/oauth/userinfo", userinfoLimiter, noStore, oidc.userinfo.bind(oidc));
  app.post("/api/auth/oauth/revoke", revokeLimiter, noStore, oidc.revoke.bind(oidc));

  // Browser-friendly OIDC login/callback — mark no-store
  app.get("/api/auth/oidc/login", authorizeLimiter, noStore, oidc.oidcLogin.bind(oidc));
  app.get("/api/auth/oidc/callback", authorizeLimiter, noStore, oidc.oidcCallback.bind(oidc));
};
