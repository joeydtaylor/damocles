// src/api/services/key.service.ts
import fs from "fs";
import path from "path";
import { createHash } from "crypto";

let _jose: any | null = null;
let _keysPromise:
  | Promise<{ privateKey: any; publicKey: any; jwk: Record<string, any>; kid: string }>
  | null = null;

const b64url = (buf: Buffer) => buf.toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");

async function getJose() {
  if (_jose) return _jose;
  _jose = await new Function("return import('jose')")();
  return _jose;
}

export class KeyService {
  constructor(private cfg: Configuration.ISecurityConfiguration["oauth"]) {}

  async load() {
    if (_keysPromise) return _keysPromise;
    _keysPromise = (async () => {
      const jose = await getJose();
      const privPem = fs.readFileSync(path.resolve(this.cfg.privateKeyPath), "utf-8");
      const pubPem  = fs.readFileSync(path.resolve(this.cfg.publicKeyPath), "utf-8");
      const privateKey = await jose.importPKCS8(privPem, this.cfg.signingAlgorithm);
      const publicKey  = await jose.importSPKI(pubPem,  this.cfg.signingAlgorithm);
      const kid = b64url(createHash("sha256").update(pubPem).digest());
      const jwk = await jose.exportJWK(publicKey);
      Object.assign(jwk, { kid, alg: this.cfg.signingAlgorithm, use: "sig" });
      return { privateKey, publicKey, jwk, kid };
    })();
    return _keysPromise;
  }

  async getJose() {
    return getJose();
  }

  readPublicPem(): string {
    return fs.readFileSync(path.resolve(this.cfg.publicKeyPath), "utf-8");
  }
}
