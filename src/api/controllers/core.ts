import { NextFunction, Request, Response } from "express";
import { ApplyConfiguration, Frozen } from "../../helpers/configuration";
import Authorization from "./auth/authorization";

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
