import fs from "fs";
import path from "path";
import { generateKeyPairSync } from "crypto";

const projectRoot = path.resolve(__dirname, "..");
const keysDir = path.join(projectRoot, "etc", "keys");

fs.mkdirSync(keysDir, { recursive: true });

const privateKeyPath = path.join(
  projectRoot,
  process.env.OAUTH_PRIVATE_KEY_PATH || "etc/keys/oauth-private.key"
);
const publicKeyPath = path.join(
  projectRoot,
  process.env.OAUTH_PUBLIC_KEY_PATH || "etc/keys/oauth-public.key"
);

// Check if both keys already exist
if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
  console.log(`Keys already exist, skipping generation:
  Private: ${privateKeyPath}
  Public:  ${publicKeyPath}`);
  process.exit(0);
}

// Generate RSA keypair
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Write keys to disk
fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });

console.log(`Generated keys:
  Private: ${privateKeyPath}
  Public:  ${publicKeyPath}`);
