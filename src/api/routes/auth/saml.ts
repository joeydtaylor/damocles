import express from "express";
import Authentication from "../../controllers/auth/authentication";

module.exports = (app: express.Application) => {
  const auth = new Authentication();

  // SAML
  app.get("/api/auth/saml/login", auth.samlLogin);
  app.post("/api/auth/saml/consume", auth.samlConsume);
};
