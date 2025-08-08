import Core from "../controllers/core.controller";
import express from "express";

module.exports = async (app: express.Application) => {
  const { index } = new Core();
  app.get("/", index);
  app.get("/api", index);
};
