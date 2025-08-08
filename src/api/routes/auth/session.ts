import express from "express";
import Authorization from "../../controllers/auth/authorization";

module.exports = (app: express.Application) => {
  const { getUserContext } = new Authorization();

  app.get("/api/auth/session/", getUserContext);
};
