// scripts/seed.ts
import fs from "fs";
import path from "path";
import { config as loadEnv } from "dotenv";
import { PrismaClient } from "@prisma/client";
import { randomUUID } from "crypto";
import bcrypt from "bcrypt";

loadEnv({ path: ".env.development" }); // adjust if you run with a different env file

const prisma = new PrismaClient();

const has = (v?: string | null) => typeof v === "string" && v.trim().length > 0;
const fileExists = (p?: string) => {
  if (!has(p)) return false;
  try {
    return fs.statSync(p!).isFile();
  } catch {
    return false;
  }
};

async function upsertClient(opts: {
  name: string;
  clientId: string;
  confidential: boolean;
  clientSecretPlain?: string;
  organizationId: string;
  redirectUris: string[];
  scopes: string[];
}) {
  const existing = await prisma.oAuthClient.findUnique({ where: { clientId: opts.clientId } });

  const clientSecret = opts.confidential
    ? await bcrypt.hash(opts.clientSecretPlain ?? "change-me", 12)
    : "";

  if (!existing) {
    await prisma.oAuthClient.create({
      data: {
        id: randomUUID(),
        name: opts.name,
        clientId: opts.clientId,
        clientSecret,
        organizationId: opts.organizationId,
        scopes: opts.scopes,
        redirectUris: opts.redirectUris,
        confidential: opts.confidential,
      },
    });
    console.log(
      `✅ Created OAuth client\n  client_id: ${opts.clientId}\n  confidential: ${opts.confidential}\n  redirect_uris: ${opts.redirectUris.join(
        ", "
      )}\n  scopes: ${opts.scopes.join(" ")}${opts.confidential ? `\n  client_secret (plain): ${opts.clientSecretPlain}` : ""}`
    );
  } else {
    await prisma.oAuthClient.update({
      where: { id: existing.id },
      data: {
        name: opts.name,
        redirectUris: opts.redirectUris,
        confidential: opts.confidential,
        scopes: existing.scopes?.length ? existing.scopes : opts.scopes,
        organizationId: existing.organizationId ?? opts.organizationId,
        ...(opts.confidential ? { clientSecret } : { clientSecret: "" }),
      },
    });
    console.log(
      `ℹ️  Updated OAuth client\n  client_id: ${opts.clientId}\n  confidential: ${opts.confidential}\n  redirect_uris: ${opts.redirectUris.join(
        ", "
      )}\n  scopes: ${existing.scopes?.length ? existing.scopes.join(" ") : opts.scopes.join(" ")}${opts.confidential ? `\n  client_secret (plain): ${opts.clientSecretPlain}` : ""}`
    );
  }
}

async function main() {
  // ---------- Detect SAML ----------
  let samlEnabled = false;
  let samlXml: string | null = null;

  const metadataPathEnv = process.env.SAML_METADATA_PATH;
  const metadataPath = metadataPathEnv
    ? path.resolve(process.cwd(), metadataPathEnv)
    : undefined;

  if (fileExists(metadataPath)) {
    try {
      samlXml = fs.readFileSync(metadataPath!, "utf8");
      if (has(samlXml)) {
        samlEnabled = true;
        console.log(`✅ SAML enabled (metadata: ${metadataPath})`);
      } else {
        console.log("⚠️  SAML metadata file is empty; SAML disabled");
      }
    } catch (e) {
      console.log(`⚠️  Failed to read SAML metadata (${metadataPath}): ${(e as Error).message}; SAML disabled`);
    }
  } else {
    console.log("ℹ️  No valid SAML metadata provided; SAML disabled");
  }

  // ---------- Detect OIDC ----------
  const oidcIssuer = process.env.OIDC_ISSUER_URL;
  const oidcClientId = process.env.OIDC_CLIENT_ID;
  const oidcClientSecret = process.env.OIDC_CLIENT_SECRET || null;
  const oidcJwksUrl = process.env.OIDC_JWKS_URL;
  const oidcScopesStr = process.env.OIDC_SCOPES;

  const oidcEnabled =
    has(oidcIssuer) && has(oidcClientId) && has(oidcJwksUrl) && has(oidcScopesStr);

  if (oidcEnabled) {
    console.log("✅ OIDC enabled (issuer/client/jwks/scopes present)");
  } else {
    console.log("ℹ️  OIDC not fully configured; skipping OIDC config");
  }

  // ---------- Organization upsert ----------
  const org = await prisma.organization.upsert({
    where: { domain: "local" },
    update: {
      samlEnabled,
      oidcEnabled,
      samlMetadataXml: samlEnabled ? samlXml : null,
    },
    create: {
      id: randomUUID(),
      domain: "local",
      name: "Local Tenant",
      samlEnabled,
      oidcEnabled,
      samlMetadataXml: samlEnabled ? samlXml : null,
    },
  });

  // ---------- OIDC config upsert (conditional) ----------
  if (oidcEnabled) {
    const scopes = (oidcScopesStr as string).split(",").map((s) => s.trim()).filter(Boolean);
    await prisma.oIDCConfig.upsert({
      where: { organizationId: org.id },
      update: {
        issuerUrl: oidcIssuer as string,
        clientId: oidcClientId as string,
        clientSecret: oidcClientSecret,
        jwksUrl: oidcJwksUrl as string,
        scopes,
      },
      create: {
        id: randomUUID(),
        organizationId: org.id,
        issuerUrl: oidcIssuer as string,
        clientId: oidcClientId as string,
        clientSecret: oidcClientSecret,
        jwksUrl: oidcJwksUrl as string,
        scopes,
      },
    });
  }

  // ---------- Built-in roles ----------
  const roleNames = [
    process.env.ADMIN_ROLE_NAME || "admin",
    process.env.DEVELOPER_ROLE_NAME || "developer",
    process.env.CONTRIBUTOR_ROLE_NAME || "contributor",
    process.env.READER_ROLE_NAME || "reader",
    process.env.AUDITOR_ROLE_NAME || "auditor",
    process.env.SUPPORT_ROLE_NAME || "support",
  ];

  for (const name of roleNames) {
    await prisma.role.upsert({
      where: { name_organizationId: { name, organizationId: org.id } },
      update: {},
      create: { id: randomUUID(), name, organizationId: org.id },
    });
  }

  // ---------- OAuth clients ----------
  const extraScopes = process.env.OAUTH_EXTRA_SCOPES
    ? process.env.OAUTH_EXTRA_SCOPES.split(",").map((s) => s.trim()).filter(Boolean)
    : [];

  await upsertClient({
    name: "Steeze Dev CLI",
    clientId: "steeze-local-cli",
    confidential: true,
    clientSecretPlain: "local-secret",
    organizationId: org.id,
    redirectUris: ["https://localhost:3000/callback", "http://localhost:3002/callback"],
    scopes: extraScopes,
  });

  await upsertClient({
    name: "Steeze Public SPA",
    clientId: "steeze-public-spa",
    confidential: false,
    organizationId: org.id,
    redirectUris: ["https://localhost:3001/callback", "http://localhost:5173/callback"],
    scopes: [...extraScopes, "openid", "profile", "email"],
  });

  console.log(
    `✅ Seeded tenant: ${org.name} (${org.domain}); roles: ${roleNames.join(", ")}; ` +
      `features → SAML=${samlEnabled} OIDC=${oidcEnabled}`
  );
}

main()
  .catch((err) => {
    console.error("❌ Seed error:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
