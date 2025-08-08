declare namespace NodeJS {
  export interface ProcessEnv {
    NODE_ENV: "production" | "development";
    PORT: string;
    APP_NAME: string;
    BASE_URL: string;
    FRONT_END_BASE_URL: string;
    LOG_DIRECTORY: string;
    LOG_MAX_SIZE_IN_NUMBER_MB: string;
    SERVER_SSL_CERTIFICATE: string;
    SERVER_SSL_PRIVATE_KEY: string;

    SAML_METADATA_PATH: string;
    SAML_SP_ENTITY_ID: string;

    REDIS_CONNECTION_STRING: string;
    SESSION_COOKIE_SECRET: string;
    SESSION_COOKIE_SAME_SITE: "lax" | "none" | "strict";
    SESSION_COOKIE_NAME: string;

    APPLICATION_COOKIE_SECRET: string;
    APPLICATION_COOKIE_SAME_SITE: "lax" | "none" | "strict";

    ADMIN_ROLE_NAME: string;
    DEVELOPER_ROLE_NAME: string;
    CONTRIBUTOR_ROLE_NAME: string;
    READER_ROLE_NAME: string;
    AUDITOR_ROLE_NAME: string;
    SUPPORT_ROLE_NAME: string;

  }
}
