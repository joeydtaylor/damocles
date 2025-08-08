import type { Request, Response, NextFunction } from "express";
import { tokenLimiter, refreshLimiter } from "./rateLimit.middleware";

/**
 * Use stricter limiter for refresh_token, otherwise the general token limiter.
 * Still run the general limiter first to protect parsing & unknown grants.
 */
export function grantAwareTokenLimiter(req: Request, res: Response, next: NextFunction) {
  // Run the general limiter first (cheap and sets headers consistently)
  (tokenLimiter as any)(req, res, (err?: any) => {
    if (err) return; // tokenLimiter already handled response

    const gt = (req.body?.grant_type || "").toString();
    if (gt === "refresh_token") {
      return (refreshLimiter as any)(req, res, next);
    }
    return next();
  });
}
