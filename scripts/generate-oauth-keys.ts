// scripts/gen-oauth-keys.ts
import fs from "fs";
import path from "path";
import { generateKeyPairSync } from "crypto";

const projectRoot = path.resolve(__dirname, ".."); // adjust if needed
const keysDir = path.join(projectRoot, "etc", "keys");

// Ensure directory exists
fs.mkdirSync(keysDir, { recursive: true });

// Generate RSA keypair
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048, // or 4096 for stronger keys
  publicKeyEncoding: {
    type: "spki", // Subject Public Key Info
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8", // PKCS#8 format
    format: "pem",
  },
});

// Write keys to disk
const privateKeyPath = path.join(keysDir, "oauth-private.key");
const publicKeyPath = path.join(keysDir, "oauth-public.key");

fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });

console.log(`Generated keys:
  Private: ${privateKeyPath}
  Public:  ${publicKeyPath}`);
