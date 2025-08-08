// src/api/controllers/auth/saml.controller.ts
import { Request, Response, NextFunction } from "express";
import passport from "passport";

type RelayState = { domain?: string; returnTo?: string };

function parseRelayStateBase64(raw: string): RelayState | null {
  try {
    const json = Buffer.from(raw, "base64").toString("utf-8");
    const obj = JSON.parse(json);
    return obj && typeof obj === "object" ? (obj as RelayState) : null;
  } catch {
    return null;
  }
}

export class SamlController {
  // GET /api/auth/saml/login
  public login = (req: Request, res: Response, next: NextFunction): void => {
    const rawRelay = (req.query.RelayState as string) || "";
    if (!rawRelay) {
      res.status(400).send("Missing RelayState");
      return;
    }

    const parsed = parseRelayStateBase64(rawRelay);
    if (!parsed) {
      res.status(400).send("Invalid RelayState encoding");
      return;
    }
    if (!parsed.domain) {
      res.status(400).send("RelayState missing 'domain'");
      return;
    }

    (req as any)._relayState = parsed;

    passport.authenticate(`saml-${parsed.domain}`, {
      session: true,
      failureRedirect: "/api",
      successRedirect: "/api",
      failureFlash: true,
      // keep the raw relay so the IdP echoes it back to ACS
      state: rawRelay,
    })(req, res, next);
  };

  // POST /api/auth/saml/consume (ACS)
  public consume = (req: Request, res: Response, next: NextFunction): void => {
    const rawRelay = (req.body?.RelayState as string) || "";
    if (!rawRelay) {
      res.status(400).send("Missing RelayState");
      return;
    }

    const parsed = parseRelayStateBase64(rawRelay);
    if (!parsed) {
      res.status(400).send("Invalid RelayState encoding");
      return;
    }
    if (!parsed.domain) {
      res.status(400).send("RelayState missing 'domain'");
      return;
    }

    (req as any)._relayState = parsed;

    passport.authenticate(`saml-${parsed.domain}`, {
      session: true,
      failureRedirect: "/api",
      successRedirect: parsed.returnTo || "/api",
      failureFlash: true,
    })(req, res, next);
  };
}

export default SamlController;
