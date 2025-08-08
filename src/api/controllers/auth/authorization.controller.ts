// src/api/controllers/auth/authorization.ts
import { Request, Response, NextFunction } from "express";
import { Frozen, ApplyConfiguration } from "../../../helpers/configuration.helper";
import Authentication from "./authentication.controller";

@Frozen
@ApplyConfiguration()
export class Authorization implements Authorization.IAuthorize {
  public app!: Configuration.IApplicationConfiguration;
  public security!: Configuration.ISecurityConfiguration;

  /**
   * Middleware for protecting a route with both authentication and authorization.
   * Keeps existing call signature: protectedRoute(req, res, next, props)
   */
  public protectedRoute = (
    req: Request,
    res: Response,
    next: NextFunction,
    props: Authorization.IAccessControlAllowList
  ): void => {
    const { authenticateUser } = new Authentication();

    // 1) Authenticate
    authenticateUser(req, res);
    if (res.headersSent) return;

    // 2) Authorize
    this.authorizeUser(req, res, next, props);
  };

  /**
   * Middleware for redirecting an already authorized user to a path (or home).
   * Keeps existing call signature: redirectAuthorizedUser(req, res, next, path?)
   * We authenticate + authorize inline so we fully control redirect flow.
   */
  public redirectAuthorizedUser = (
    req: Request,
    res: Response,
    _next: NextFunction,
    _path?: string
  ): void => {
    const { authenticateUser } = new Authentication();

    // 1) Authenticate
    authenticateUser(req, res);
    if (res.headersSent) return;

    // 2) Authorize (all authenticated)
    this.authorizeUser(req, res, undefined, { allow: "allAuthenticated" });
    if (res.headersSent) return;

    // 3) Redirect logic
    if (req.user && _path) {
      res.redirect(_path);
      return;
    }
    if (req.user && !_path) {
      res.redirect(this.app.frontEndBaseUrl);
      return;
    }
    res.redirect(`${this.app.frontEndBaseUrl}/login`);
  };

  /**
   * Core authorization logic — checks if a user is allowed based on config.
   */
  private authorizeUser = (
    req: Request,
    res: Response,
    next?: NextFunction,
    props?: Authorization.IAccessControlAllowList
  ): void => {
    const isAuthenticated = Boolean(req.user?.id && req.user?.organizationId);
    const userRoles = Array.isArray(req.user?.roles) ? req.user.roles : [];

    const adminRoleName = this.security.authorization.roles.admin.name;

    const isAllowed =
      (props?.allow === "allAuthenticated" && isAuthenticated) ||
      userRoles.includes(adminRoleName) ||
      props?.allow?.some?.((r: string) => userRoles.includes(r));

    if (isAllowed) {
      if (req.user) (req.user as any).isAuthorized = true;
      if (next) next();
      return;
    }

    if (!res.headersSent) {
      res.status(401).json({
        type: "error",
        message: "Unauthorized",
      } as Service.JsonMessageContext);
    }
  };

  /**
   * Returns the current authenticated user's context.
   */
  public getUserContext = (req: Request, res: Response): void => {
    if (req.user) {
      res.status(200).json({
        id: (req.user as any).id,
        email: (req.user as any).email,
        username: (req.user as any).username,
        organizationId: (req.user as any).organizationId,
        roles: (req.user as any).roles,
        role: { name: (req.user as any).role },
      });
      return;
    }

    res.status(401).json({
      message: "Unauthorized",
      type: "error",
    } as Service.JsonMessageContext);
  };
}

export default Authorization;
