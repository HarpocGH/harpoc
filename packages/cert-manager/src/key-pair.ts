import { generateKeyPairSync } from "node:crypto";

export interface KeyPairOptions {
  algorithm: "rsa" | "ec";
  modulusLength?: 2048 | 4096;
  namedCurve?: "P-256" | "P-384";
}

export function generateCertKeyPair(options: KeyPairOptions): {
  privateKeyPem: string;
  publicKeyPem: string;
} {
  if (options.algorithm === "rsa") {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: options.modulusLength ?? 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    return { privateKeyPem: privateKey, publicKeyPem: publicKey };
  }
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: options.namedCurve ?? "P-256",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}
