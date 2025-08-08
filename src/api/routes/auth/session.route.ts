// src/api/routes/auth/session.ts
import express from "express";
import Authorization from "../../controllers/auth/authorization.controller";
import { cacheSessionContext } from "../../../middleware/cache/cache.middleware";

module.exports = (app: express.Application) => {
  const { getUserContext } = new Authorization();
  app.get("/api/auth/session", cacheSessionContext(getUserContext));
};
