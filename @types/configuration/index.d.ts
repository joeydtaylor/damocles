declare namespace Configuration {
  // Cookies
  export interface IApplicationCookieConfiguration {
    signed: boolean;
    secure: boolean;
    httpOnly: boolean;
    sameSite: "lax" | "strict" | "none";
    secret: string;
  }

  export interface ISessionCookieConfiguration {
    secret: string;
    sameSite: "lax" | "strict" | "none";
    secure: boolean;
    httpOnly: boolean;
    name: string;
    signed: boolean;
    maxAgeInHours: number;
  }

  // Logging
  export interface ILoggingConfiguration {
    logDir: string;
    logRetentionInDays: number;
    logMaxSizeInNumberMB: number; // numeric
    logMaxFilecount: number;
  }

  // Sessions
  export interface ISessionStoreConfiguration {
    redisConnectionString: string;
    cookie: ISessionCookieConfiguration;
    resave: boolean;
    saveUninitialized: boolean;
  }

  // SAML
  interface ISamlAuthenticationConfiguration {
    enabled: boolean;
    strategy: string;
    spPrivateKey: string;
    spPublicCertificate: string;
    path: string;
    issuer: string;
    samlMetadataPath: string;
  }

  // OAuth2/OIDC
  export interface IOAuthConfiguration {
    privateKeyPath: string;
    publicKeyPath: string;
    signingAlgorithm: "RS256" | "ES256";
    issuer: string;
    audience: string;
    accessTokenTtlSeconds: number;
    enforceS256Pkce: boolean;
    allowHeaderUser: boolean;     // dev/testing header bypass
    jwksCacheSeconds: number;     // cache hints for JWKS/PEM endpoints
    extraScopes: string[];        // <-- NEW, always defined
    refreshTokenTtlSeconds: number;
  }


  // AuthN/AuthZ root
  export interface IAuthenticationConfiguration {
    samlConfiguration: ISamlAuthenticationConfiguration;
    sessionStoreConfiguration: ISessionStoreConfiguration;
    applicationCookieConfiguration: IApplicationCookieConfiguration;
  }

  export interface IAuthorizationConfiguration {
    roles: Authorization.IRoles;
  }

  // Security root
  export interface ISecurityConfiguration {
    corsOrigin: Array<string>;
    serverSslCertificate: string;
    serverSslPrivateKey: string;
    authentication: IAuthenticationConfiguration;
    authorization: IAuthorizationConfiguration;
    oauth: IOAuthConfiguration; // <-- new
  }

  // App
  export interface IApplicationConfiguration {
    name: string;
    port: number;
    logging: ILoggingConfiguration;
    baseUrl: string;
    frontEndBaseUrl: string;
  }

  // Top-level
  export interface ISchema {
    app: IApplicationConfiguration;
    security: ISecurityConfiguration;
  }

  // User context passed on req.user
  export interface IUserContext {
    id: string;
    email: string;
    username: string;
    roles: string[];
    role: string; // primary role
    organizationId: string;
    authenticationSource?: "saml" | "oauth2";
    isAuthorized?: boolean;
  }
}
