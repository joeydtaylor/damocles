// src/middleware/security/noStore.middleware.ts
import type { Request, Response, NextFunction } from "express";

export function noStore(_req: Request, res: Response, next: NextFunction) {
  // Prevent intermediaries/browsers from caching auth responses
  res.setHeader("Cache-Control", "no-store");   // RFC 6749 §5.1
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
}
