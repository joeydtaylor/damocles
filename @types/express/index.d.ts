declare namespace Express {
  export interface Request {
    user?: any;
    headers?: any;
    sessionExpires?: Date;
    rememberMe?: boolean;
    files?: fileUpload.FileArray;
    _relayState?: {
      domain?: string;
      returnTo?: string;
      [key: string]: any;
    };
  }

  export interface Response {
    change?: any;
  }
}
