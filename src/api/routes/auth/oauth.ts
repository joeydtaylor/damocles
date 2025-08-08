import express from "express";
import Authentication from "../../controllers/auth/authentication";
import {
  authorizeLimiter,
  introspectLimiter,
} from "../../../middleware/security/rateLimit";
import { grantAwareTokenLimiter } from "../../../middleware/security/grantAwareLimiter";
import { noStore } from "../../../middleware/security/noStore";

module.exports = (app: express.Application) => {
  const auth = new Authentication();

  // ----- OAuth2: JWKS + Public Key -----
  app.get("/api/auth/oauth/jwks.json", auth.jwks.bind(auth));
  app.get("/api/auth/oauth/public-key.pem", auth.publicKeyPem.bind(auth));

  // ----- OAuth2: Authorization Code + PKCE -----
  app.get("/api/auth/oauth/authorize", authorizeLimiter, noStore, auth.authorize.bind(auth));

  // ----- OAuth2: Token endpoint (client_credentials + authorization_code + refresh_token) -----
  app.post("/api/auth/oauth/token", grantAwareTokenLimiter, noStore, auth.token.bind(auth));

  // ----- OAuth2: Introspection -----
  app.post("/api/auth/oauth/introspect", introspectLimiter, noStore, auth.introspect.bind(auth));
};
