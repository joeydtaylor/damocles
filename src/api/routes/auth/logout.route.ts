// src/api/routes/auth/logout.ts
import express from "express";
import Authentication from "../../controllers/auth/authentication.controller";
// Optional: clear cache entry on logout if you store sid earlier in the request.
// import { sessionContextCache } from "../../../middleware/cache/sessionContextCache";

module.exports = (app: express.Application) => {
  const { logout } = new Authentication();

  app.get("/api/auth/logout", (req, res) => {
    // If you capture SID before destroy, you can evict cache here:
    // const sid = (req.signedCookies?.s || req.cookies?.s || req.sessionID) as string | undefined;
    // if (sid) sessionContextCache.delete(sid);
    logout(req, res);
  });
};
