// src/api/controllers/auth/authentication.ts
import { Request, Response, NextFunction } from "express";
import { Frozen, ApplyConfiguration } from "../../../helpers/configuration.helper";
import { OAuthController } from "./oauth.controller";
import { SamlController } from "./saml.controller";

@Frozen
@ApplyConfiguration()
export class Authentication implements Authorization.IAuthenticate {
  public app!: Configuration.IApplicationConfiguration;
  public security!: Configuration.ISecurityConfiguration;

  private _oauth?: OAuthController;
  private _saml?: SamlController;

  private get oauth(): OAuthController {
    if (!this._oauth) this._oauth = new OAuthController(this.security);
    return this._oauth;
  }

  private get saml(): SamlController {
    if (!this._saml) this._saml = new SamlController();
    return this._saml;
  }

  /* ──────────────────────────────
   * SAML (delegates)
   * ────────────────────────────── */
  public samlLogin = (req: Request, res: Response, next: NextFunction): void => {
    this.saml.login(req, res, next);
  };

  public samlConsume = (req: Request, res: Response, next: NextFunction): void => {
    this.saml.consume(req, res, next);
  };

  /* ──────────────────────────────
   * Session helpers
   * ────────────────────────────── */
  public logout = (req: Request, res: Response): void => {
    const cookieCfg = this.security.authentication.sessionStoreConfiguration.cookie;

    req.session.destroy((err) => {
      if (err) {
        // Do not leak details; redirect to login UX
        res.redirect(`${this.app.frontEndBaseUrl}/login`);
        return;
      }

      res.clearCookie(cookieCfg.name, {
        httpOnly: cookieCfg.httpOnly,
        secure: cookieCfg.secure,
        sameSite: cookieCfg.sameSite,
        signed: cookieCfg.signed,
        path: "/",
      });

      res.status(200).json({ message: "successfully logged out", type: "success" });
    });
  };

  /**
   * Authentication gate.
   * - Works as a function (old usage): authenticateUser(req,res)
   * - Works as middleware (preferred): authenticateUser(req,res,next)
   */
  public authenticateUser = (req: Request, res: Response, next?: NextFunction): void => {
    const isSessionAuth = Boolean(req.isAuthenticated?.() && req.user?.id && req.user?.organizationId);
    const isTokenAuth = Boolean(
      req.user?.id && req.user?.organizationId && req.user?.authenticationSource === "oauth2"
    );

    if (isSessionAuth || isTokenAuth) {
      if (req.user && !req.user.authenticationSource) {
        req.user.authenticationSource = isSessionAuth ? "saml" : "oauth2";
      }
      if (next) return next();
      return;
    }

    if (!res.headersSent) {
      res.status(401).json({ message: "Unauthorized", type: "error" });
    }
  };

  /* ──────────────────────────────
   * OAuth (delegates)
   * ────────────────────────────── */
  public jwksWellKnown = async (req: Request, res: Response): Promise<void> => {
    await this.oauth.jwksWellKnown(req, res);
  };

  public jwks = async (req: Request, res: Response): Promise<void> => {
    await this.oauth.jwks(req, res);
  };

  public publicKeyPem = async (req: Request, res: Response): Promise<void> => {
    await this.oauth.publicKeyPem(req, res);
  };

  public authorize = async (req: Request, res: Response): Promise<void> => {
    await this.oauth.authorize(req, res);
  };

  public token = async (req: Request, res: Response): Promise<void> => {
    await this.oauth.token(req, res);
  };

  public introspect = async (req: Request, res: Response): Promise<void> => {
    await this.oauth.introspect(req, res);
  };
}

export default Authentication;
