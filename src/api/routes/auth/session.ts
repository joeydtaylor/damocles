// src/api/routes/auth/session.ts
import express from "express";
import Authorization from "../../controllers/auth/authorization";
import { cacheSessionContext } from "../../../middleware/cache/sessionContextCache";

module.exports = (app: express.Application) => {
  const { getUserContext } = new Authorization();
  app.get("/api/auth/session", cacheSessionContext(getUserContext));
};
