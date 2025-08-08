# 🛡 Aegis Auth

A **production-grade**, **multi-tenant** authentication and authorization service built with **TypeScript**, **Node.js**, and **Express**. Designed with **FedRAMP**, **HIPAA**, and other high-assurance compliance frameworks in mind, Aegis Auth implements strict security controls while supporting **SAML 2.0**, **OAuth 2.0** (Authorization Code + PKCE, Client Credentials, Refresh Token), and **OIDC** flows. It includes advanced **RBAC**, Redis-backed secure sessions, and configurable per-tenant SSO.

---

## ✨ Features

* 🏢 **Multi-Tenant SSO** — Dynamic routing and metadata per tenant.
* 🔑 **OAuth 2.0 & OIDC** — Full token lifecycle with PKCE enforcement.
* 📄 **Dynamic SAML Metadata** — Per-tenant SAML configuration with runtime loading.
* 📊 **RBAC** — Configurable role hierarchy with least-privilege defaults.
* 🛡 **Security Defaults** — Strict TLS, secure cookies, SameSite enforcement, CSRF mitigation, and per-endpoint rate limiting.
* 🗄 **Session Security** — Redis-backed sessions with tamper-resistant signing and idle timeout enforcement.
* 📈 **Observability** — Prometheus metrics, structured JSON logging, and optional SIEM forwarding.
* ⚡ **Scalable** — Stateless token flows, container-ready, and Kubernetes/Fargate compatible.

---

## 📂 Project Structure

```
src/
├── api/routes/auth/       # Auth-related route definitions
├── controllers/auth/      # SAML, OAuth, OIDC controllers
├── middleware/            # Auth, logging, rate limiting, security
├── helpers/               # Global configuration loader/decorators
├── prisma/                # Prisma schema & migrations
└── app.ts                 # Application entrypoint
```

---

## 🛠 Getting Started

### 1️⃣ Create `.env.development`

```bash
cp .env.example .env.development
```

Populate all required values, ensuring database, Redis, TLS, and key paths are set.

---

### 2️⃣ SSL Certificate Setup

**Option A — Use provided certificate:**

1. Locate `etc/keys/devServerSslCertificate.crt`.
2. Add to local trusted root:

   * **macOS:** Add to System keychain, mark *Always Trust*.
   * **Linux:** Copy to `/usr/local/share/ca-certificates/` then `sudo update-ca-certificates`.
   * **Windows:** Install into *Trusted Root Certification Authorities*.

**Option B — Generate your own:**

```bash
mkdir -p etc/keys
openssl req -x509 -newkey rsa:4096 -nodes -keyout etc/keys/devServerSslCertificate.key -out etc/keys/devServerSslCertificate.crt -days 365 -subj "/CN=localhost"
```

---

### 3️⃣ Generate OAuth2 Keys

```bash
yarn oauth:generate:keys
```

### 4️⃣ Start Dependencies

```bash
docker compose build
docker compose up -d
```

### 5️⃣ Initialize Database

```bash
yarn prisma:init:local
```

### 6️⃣ Seed Local Tenant

```bash
yarn prisma:seed:tenant
```

---

## 📜 Available Scripts

| Script                     | Description                      |
| -------------------------- | -------------------------------- |
| `yarn dev`                 | Start dev server with hot reload |
| `yarn start`               | Run compiled app in production   |
| `yarn build`               | Compile TypeScript               |
| `yarn prisma:generate`     | Generate Prisma client           |
| `yarn prisma:push`         | Push schema to DB                |
| `yarn prisma:studio`       | Open Prisma Studio               |
| `yarn prisma:seed:tenant`  | Seed a local tenant              |
| `yarn prisma:init:local`   | Push schema & generate client    |
| `yarn prisma:reset:local`  | Reset DB and seed tenant         |
| `yarn oauth:generate:keys` | Generate OAuth key pair          |

---

## 🌐 Endpoints Overview

**SAML**

* `GET /api/auth/saml/login` — Initiate login
* `POST /api/auth/saml/consume` — ACS endpoint

**OAuth2**

* `GET /api/auth/oauth/authorize` — Auth endpoint
* `POST /api/auth/oauth/token` — Token issuance
* `POST /api/auth/oauth/introspect` — Token introspection
* `GET /api/auth/oauth/jwks.json` — JWKS
* `GET /api/auth/oauth/public-key.pem` — Public key

**OIDC**

* `GET /.well-known/openid-configuration` — Discovery
* `GET /.well-known/jwks.json` — JWKS for OIDC
* `GET /api/auth/oauth/userinfo` — UserInfo
* `POST /api/auth/oauth/revoke` — Token revocation
* `GET /api/auth/oidc/login` — OIDC login
* `GET /api/auth/oidc/callback` — OIDC callback

---

## 🔒 Security Highlights

* **Compliance Alignment** — Built to meet FedRAMP/HIPAA requirements with hardened defaults (final certification requires deployment-specific controls).
* **TLS 1.2/1.3 Enforcement** — Strong cipher suites only.
* **HSTS Preload** — Strict HTTPS everywhere.
* **CSRF Protection** — Tokens and SameSite policies.
* **DoS Protection** — Per-endpoint rate limiting.
* **Audit Logging** — Structured event logs for all auth events.
* **Key Management Ready** — Designed for integration with KMS or Secrets Manager for secure key storage.

---

## 📊 Observability

* `/metrics` — Prometheus endpoint
* Structured JSON logs with PII redaction
* Optional SIEM integration with batching and failover persistence

---

## 🏗 Technology Stack

* **Runtime**: Node.js + TypeScript
* **Framework**: Express.js
* **Auth**: Passport.js, jose, passport-saml
* **DB**: PostgreSQL + Prisma ORM
* **Cache/Sessions**: Redis + connect-redis
* **Security**: Helmet, CORS, TLS, HSTS
* **Metrics**: Prometheus
