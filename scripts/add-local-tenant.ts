// scripts/seed.ts
import fs from "fs";
import path from "path";
import { config as loadEnv } from "dotenv";
import { PrismaClient } from "@prisma/client";
import { randomUUID } from "crypto";
import bcrypt from "bcrypt";

loadEnv({ path: ".env.development" }); // adjust if you run with a different env file

const prisma = new PrismaClient();

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
        ...(opts.confidential
          ? { clientSecret }
          : { clientSecret: "" }),
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
  const samlEnabled = true;
  const oidcEnabled = true;

  let samlXml: string | null = null;
  if (samlEnabled) {
    const metadataPath = process.env.SAML_METADATA_PATH;
    if (!metadataPath) throw new Error("SAML_METADATA_PATH not set in env");
    samlXml = fs.readFileSync(path.resolve(metadataPath), "utf-8");
  }

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

  if (oidcEnabled) {
    await prisma.oIDCConfig.upsert({
      where: { organizationId: org.id },
      update: {
        issuerUrl: process.env.OIDC_ISSUER_URL!,
        clientId: process.env.OIDC_CLIENT_ID!,
        clientSecret: process.env.OIDC_CLIENT_SECRET || null,
        jwksUrl: process.env.OIDC_JWKS_URL!,
        scopes: process.env.OIDC_SCOPES!.split(",").map(s => s.trim()),
      },
      create: {
        id: randomUUID(),
        organizationId: org.id,
        issuerUrl: process.env.OIDC_ISSUER_URL!,
        clientId: process.env.OIDC_CLIENT_ID!,
        clientSecret: process.env.OIDC_CLIENT_SECRET || null,
        jwksUrl: process.env.OIDC_JWKS_URL!,
        scopes: process.env.OIDC_SCOPES!.split(",").map(s => s.trim()),
      },
    });
  }

  const builtinRoles = [
    process.env.ADMIN_ROLE_NAME!,
    process.env.DEVELOPER_ROLE_NAME!,
    process.env.CONTRIBUTOR_ROLE_NAME!,
    process.env.READER_ROLE_NAME!,
    process.env.AUDITOR_ROLE_NAME!,
    process.env.SUPPORT_ROLE_NAME!,
  ];
  for (const name of builtinRoles) {
    await prisma.role.upsert({
      where: { name_organizationId: { name, organizationId: org.id } },
      update: {},
      create: { id: randomUUID(), name, organizationId: org.id },
    });
  }

  const extraScopes = process.env.OAUTH_EXTRA_SCOPES
    ? process.env.OAUTH_EXTRA_SCOPES.split(",").map(s => s.trim())
    : [];

  await upsertClient({
    name: "Steeze Dev CLI",
    clientId: "steeze-local-cli",
    confidential: true,
    clientSecretPlain: "local-secret",
    organizationId: org.id,
    redirectUris: [
      "https://localhost:3000/callback",
      "http://localhost:3002/callback",
    ],
    scopes: extraScopes,
  });

  await upsertClient({
    name: "Steeze Public SPA",
    clientId: "steeze-public-spa",
    confidential: false,
    organizationId: org.id,
    redirectUris: [
      "https://localhost:3001/callback",
      "http://localhost:5173/callback",
    ],
    scopes: [...extraScopes, "openid", "profile", "email"],
  });

  console.log(`✅ Seeded tenant: ${org.name} (${org.domain}); roles: ${builtinRoles.join(", ")}`);
}

main()
  .catch((err) => {
    console.error("❌ Seed error:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
