// src/api/controllers/core.controller.ts
import { NextFunction, Request, Response } from "express";
import { ApplyConfiguration, Frozen } from "../../helpers/configuration.helper";
import Authorization from "./auth/authorization.controller";

@Frozen
@ApplyConfiguration()
export class Core {
  public app!: Configuration.IApplicationConfiguration;

  public index = (req: Request, res: Response, next: NextFunction): void => {
    const { redirectAuthorizedUser } = new Authorization();

    redirectAuthorizedUser(req, res, next, this.app.frontEndBaseUrl);
  };
}

export default Core;
