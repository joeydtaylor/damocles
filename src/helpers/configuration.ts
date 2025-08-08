import config from "../config/config";

config.security.corsOrigin = [...config.security.corsOrigin];
config.security.corsOrigin.push(config.app.baseUrl);
config.security.corsOrigin.push(config.app.frontEndBaseUrl);

export const Frozen = (constructor: Function) => {
  Object.freeze(constructor);
  Object.freeze(constructor.prototype);
};

export const ApplyConfiguration =
  (_options?: any[]) =>
  <T extends { new (...args: any[]): {} }>(constructor: T) => {
    class ApplicationConfiguration extends constructor {
      app: Configuration.IApplicationConfiguration = config.app;
    }

    class SecurityConfiguration extends ApplicationConfiguration {
      security: Configuration.ISecurityConfiguration = config.security;
    }

    const className = constructor.name;
    if (
      className === "Authentication" ||
      className === "Authorization" ||
      className === "GlobalConfiguration"
    ) {
      return class extends SecurityConfiguration {};
    } else {
      return class extends ApplicationConfiguration {};
    }
  };

@ApplyConfiguration()
class GlobalConfiguration implements Configuration.ISchema {
  app!: Configuration.IApplicationConfiguration;
  security!: Configuration.ISecurityConfiguration;
}

export const globalConfiguration = new GlobalConfiguration();

export { config, GlobalConfiguration };
