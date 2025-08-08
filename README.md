# ⚔ Damocles

**Damocles** is the **guardian of trust** in the Steeze Stack — a **production-grade**, **multi-tenant** authentication and authorization service built with **TypeScript**, **Node.js**, and **Express**.

Like the sword it’s named for, Damocles hangs over every request, ensuring **only the rightful may pass**. It enforces high-assurance security controls designed for **FedRAMP**, **HIPAA**, and other rigorous compliance frameworks, while remaining lean enough to integrate seamlessly with the rest of the stack.

Damocles supports:

* **SAML 2.0** — per-tenant federation with dynamic metadata.
* **OAuth 2.0** — Authorization Code + PKCE, Client Credentials, Refresh Token.
* **OpenID Connect (OIDC)** — single-issuer first-party token service.
* Advanced **RBAC** — per-tenant role hierarchy.
* Redis-backed secure sessions.
* Configurable SSO on a per-tenant basis.

---

## ✨ Features

* 🏢 **Multi-Tenant SSO** — Dynamic routing and metadata per tenant (SAML).
* 🔑 **OAuth 2.0 & OIDC** — Full token lifecycle with PKCE enforcement.
* 📄 **Dynamic SAML Metadata** — Per-tenant XML metadata loading.
* 📊 **RBAC** — Configurable role hierarchy with least-privilege defaults.
* 🛡 **Security Defaults** — TLS, secure cookies, SameSite, CSRF mitigation, per-endpoint rate limiting.
* 🗄 **Session Security** — Redis-backed with tamper protection and idle timeout enforcement.
* 📈 **Observability** — Prometheus metrics, structured JSON logging, optional SIEM forwarding.
* ⚡ **Scalable** — Stateless token flows, container-ready, Kubernetes/Fargate friendly.

---

## 📂 Project Structure

```
scripts/                # Helper/Build scripts
prisma/                 # Prisma schema, migrations
src/
├── api/routes/auth/    # Auth route definitions
├── controllers/auth/   # SAML, OAuth, OIDC controllers
├── middleware/         # Security, logging, rate limiting
├── helpers/            # Config loader, decorators
└── app.ts              # Express entrypoint
```

---

## 🛠 Getting Started

### 1️⃣ Environment Setup

```bash
cp .env.example .env.development
```

Fill in:

* **Database**: `DATABASE_URL` for Prisma.
* **Redis**: `REDIS_URL`.
* **Session**: `SESSION_COOKIE_SECRET`.
* **Signing keys**: `OAUTH_PRIVATE_KEY_PATH`, `OAUTH_PUBLIC_KEY_PATH` (bootstrap generates).
* **SAML metadata path** if using SAML.
* **OIDC** fields if using upstream OIDC.

---

### 2️⃣ Dev TLS Certificate

**Option A — Use provided cert**

1. Locate `etc/keys/devServerSslCertificate.crt`.
2. Add to OS trust store.

**Option B — Generate your own**

```bash
mkdir -p etc/keys
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout etc/keys/devServerSslCertificate.key \
  -out    etc/keys/devServerSslCertificate.crt \
  -days 365 -subj "/CN=localhost"
```

---

### 3️⃣ Build & Start

```bash
docker compose up --build
```

**Startup sequence:**

1. Postgres + Redis containers start.
2. `damocles-migrate` runs:

   * Generates OAuth signing keys into `etc/keys`.
   * Runs Prisma migrations.
   * Seeds DB with:

     * Roles.
     * OAuth clients.
     * **SAML** config if `SAML_METADATA_PATH` is valid.
     * **OIDC** config if OIDC env vars are valid.
3. `damocles` launches with hot reload (`yarn dev`).

---

## 📜 Scripts

| Script                     | Description                                  |
| -------------------------- | -------------------------------------------- |
| `yarn dev`                 | Start dev server with hot reload             |
| `yarn start`               | Run compiled app in production               |
| `yarn build`               | Compile TypeScript                           |
| `yarn prisma:generate`     | Generate Prisma client                       |
| `yarn prisma:push`         | Push schema to DB                            |
| `yarn prisma:studio`       | Open Prisma Studio                           |
| `yarn prisma:seed:tenant`  | Seed tenant roles, clients, SAML/OIDC config |
| `yarn prisma:init:local`   | Push schema & generate client                |
| `yarn prisma:reset:local`  | Reset DB and reseed                          |
| `yarn oauth:generate:keys` | Generate OAuth signing key pair              |

---

## 🌐 Endpoints Overview

**SAML**

* `GET /api/auth/saml/login` — Initiate login. Supports `RelayState` for post-login redirect:

  ```bash
  https://localhost:3000/api/auth/saml/login?RelayState=eyJkb21haW4iOiJsb2NhbCIsInJldHVyblRvIjoiaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbSJ9
  ```

  Decodes to:

  ```json
  { "domain": "local", "returnTo": "https://www.google.com" }
  ```

  * `domain` must match an existing tenant.
  * `returnTo` must be a safe URL (validated server-side).

* `POST /api/auth/saml/consume` — Assertion Consumer Service.

**OAuth2**

* `GET /api/auth/oauth/authorize` — Auth endpoint.
* `POST /api/auth/oauth/token` — Token issuance.
* `POST /api/auth/oauth/introspect` — Token introspection.
* `GET /api/auth/oauth/jwks.json` — JWKS.
* `GET /api/auth/oauth/public-key.pem` — Public key.

**OIDC** (Single Issuer — first-party tokens only)

* `GET /.well-known/openid-configuration` — Discovery doc.
* `GET /.well-known/jwks.json` — JWKS.
* `GET /api/auth/oauth/userinfo` — UserInfo endpoint.
* `POST /api/auth/oauth/revoke` — Token revocation.
* `GET /api/auth/oidc/login` — Login (single-issuer).
* `GET /api/auth/oidc/callback` — Callback.

---

## 🔒 Security Highlights

* **FedRAMP/HIPAA-aligned defaults** out of the box.
* TLS 1.2/1.3 enforced.
* HSTS preload-ready.
* CSRF prevention.
* Per-endpoint rate limits.
* Structured audit logging.
* KMS/Secrets Manager-ready for signing keys.

---

## 📊 Observability

* `/metrics` — Prometheus metrics.
* JSON logs with PII redaction.
* Optional SIEM push with retry & failover.

---

## 🏗 Technology Stack

* **Runtime**: Node.js + TypeScript
* **Framework**: Express.js
* **Auth**: Passport.js, jose, passport-saml
* **DB**: PostgreSQL + Prisma ORM
* **Cache/Sessions**: Redis + connect-redis
* **Security**: Helmet, CORS, TLS, HSTS
* **Metrics**: Prometheus
