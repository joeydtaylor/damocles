import { MetadataReader, toPassportConfig } from "passport-saml-metadata";
import { Strategy as SamlStrategy } from "passport-saml";
import passport from "passport";
import { PrismaClient } from "@prisma/client";

interface SessionUser {
  id: string;
  email: string;
  username: string;
  role: string; // primary role
  roles: string[];
  organizationId: string;
  authenticationSource: string;
}

module.exports = async (
  passportInstance: passport.Authenticator,
  config: Configuration.ISchema
): Promise<void> => {
  const prisma = new PrismaClient();

  const orgs = await prisma.organization.findMany({
    where: {
      samlMetadataXml: {
        not: undefined,
      },
    },
    select: {
      domain: true,
      samlMetadataXml: true,
    },
  });

  for (const org of orgs) {
    if (!org.domain || !org.samlMetadataXml) continue;

    const reader = new MetadataReader(org.samlMetadataXml);
    const idpConfig = toPassportConfig(reader);

    const spConfig = {
      path: config.security.authentication.samlConfiguration.path,
      issuer: config.security.authentication.samlConfiguration.issuer,
      passReqToCallback: true,
    };

    passportInstance.use(
      `saml-${org.domain}`,
      new SamlStrategy({ ...idpConfig, ...spConfig }, async (req: any, profile: any, done: any) => {
        try {
          const relayRaw = req.body.RelayState;
          if (!relayRaw) return done(null, false);

          let relay: { domain?: string; returnTo?: string };
          try {
            relay = JSON.parse(Buffer.from(relayRaw, "base64").toString("utf-8"));
          } catch {
            return done(null, false, { message: "Invalid RelayState encoding" });
          }

          const domain = relay.domain;
          if (!domain) return done(null, false, { message: "Missing domain in RelayState" });

          req._relayState = relay;

          const email =
            profile.email ||
            profile.nameID ||
            profile["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"];

          if (!email) return done(null, false);

          const tenant = await prisma.organization.findUnique({
            where: { domain },
          });
          if (!tenant) return done(null, false);

          const samlRolesRaw =
            profile["https://aws.amazon.com/SAML/Attributes/Role"] ||
            profile["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"] ||
            profile["role"] ||
            profile["roles"];

          const samlRoles: string[] = Array.isArray(samlRolesRaw)
            ? samlRolesRaw
            : typeof samlRolesRaw === "string"
              ? [samlRolesRaw]
              : [];

          const validRoles = await prisma.role.findMany({
            where: {
              name: { in: samlRoles },
              organizationId: tenant.id,
            },
          });

          if (validRoles.length === 0) return done(null, false);

          const primaryRole = validRoles[0]!;

          let user = await prisma.user.findUnique({
            where: { email },
            include: { roles: true },
          });

          if (!user) {
            user = await prisma.user.create({
              data: {
                email,
                organizationId: tenant.id,
                roles: {
                  connect: validRoles.map((r) => ({ id: r.id })),
                },
              },
              include: { roles: true },
            });
          } else {
            user = await prisma.user.update({
              where: { email },
              data: {
                roles: {
                  set: validRoles.map((r) => ({ id: r.id })),
                },
              },
              include: { roles: true },
            });
          }

          const sessionUser: SessionUser = {
            id: user.id,
            email: user.email,
            username: user.email,
            role: primaryRole.name,
            roles: validRoles.map((r) => r.name),
            organizationId: tenant.id,
            authenticationSource: "saml",
          };

          return done(null, sessionUser);
        } catch (err) {
          console.error("SAML strategy error:", err);
          return done(err);
        }
      })
    );
  }

  passportInstance.serializeUser((user: any, done) => {
    done(null, user);
  });

  passportInstance.deserializeUser((user: any, done) => {
    done(null, user);
  });

  await prisma.$disconnect();
};
