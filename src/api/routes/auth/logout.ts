import express from "express";
import Authentication from "../../controllers/auth/authentication";

module.exports = (app: express.Application) => {
  const { logout } = new Authentication();

  app.get("/api/auth/logout", logout);
};
