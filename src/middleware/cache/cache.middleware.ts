// src/middleware/cache/cache.middleware.ts
import { LRUCache } from "lru-cache";
import type { Request, Response, NextFunction } from "express";

type SessionBody = Record<string, unknown>;

export const sessionContextCache = new LRUCache<string, SessionBody>({
  max: 5000,
  ttl: 30_000, // 30s
});

export function cacheSessionContext(
  handler: (req: Request, res: Response, next: NextFunction) => any
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const sid = (req.signedCookies?.s || req.cookies?.s || req.sessionID) as string | undefined;
    if (!sid) return handler(req, res, next);

    const hit = sessionContextCache.get(sid);
    if (hit) {
      res.setHeader("Cache-Control", "private, max-age=30");
      return res.status(200).json(hit);
    }

    const originalJson = res.json.bind(res);
    res.json = (body: any) => {
      if (res.statusCode === 200 && body && typeof body === "object") {
        sessionContextCache.set(sid, body);
      }
      res.setHeader("Cache-Control", "private, max-age=30");
      return originalJson(body);
    };

    return handler(req, res, next);
  };
}
