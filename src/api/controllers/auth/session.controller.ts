import { Request, Response } from "express";

export class AuthSession {
  constructor(private cfg: Configuration.IAuthenticationConfiguration["sessionStoreConfiguration"]["cookie"],
              private appBaseUrl: string) {}

  authenticateUser(req: Request, res: Response): void {
    const isSession = !!(req.isAuthenticated?.() && req.user?.id && req.user?.organizationId);
    const isToken   = !!(req.user?.id && req.user?.organizationId && req.user?.authenticationSource === "oauth2");
    if (isSession || isToken) {
      if (!req.user?.authenticationSource && req.user) req.user.authenticationSource = isSession ? "saml" : "oauth2";
      return;
    }
    if (!res.headersSent) res.status(401).json({ message: "Unauthorized", type: "error" });
  }

  logout(req: Request, res: Response): void {
    req.session.destroy((err) => {
      if (err) {
        return res.redirect(`${this.appBaseUrl}/login`);
      }
      res.clearCookie(this.cfg.name, {
        httpOnly: this.cfg.httpOnly, secure: this.cfg.secure, sameSite: this.cfg.sameSite, signed: this.cfg.signed, path: "/",
      });
      res.status(200).json({ message: "successfully logged out", type: "success" });
    });
  }
}
