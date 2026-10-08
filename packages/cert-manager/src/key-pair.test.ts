import { describe, expect, it } from "vitest";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { generateCertKeyPair } from "./key-pair.js";

describe("generateCertKeyPair", () => {
  it("generates RSA 2048 PEM pairs", () => {
    const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm: "rsa" });
    expect(privateKeyPem).toMatch(/^-----BEGIN PRIVATE KEY-----\n/);
    expect(publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----\n/);
    const key = createPrivateKey(privateKeyPem);
    expect(key.asymmetricKeyType).toBe("rsa");
    expect(key.asymmetricKeyDetails?.modulusLength).toBe(2048);
    expect(createPublicKey(publicKeyPem).asymmetricKeyDetails?.modulusLength).toBe(2048);
  });

  it("generates RSA 4096 on request", () => {
    const { privateKeyPem } = generateCertKeyPair({ algorithm: "rsa", modulusLength: 4096 });
    expect(createPrivateKey(privateKeyPem).asymmetricKeyDetails?.modulusLength).toBe(4096);
  });
  it("generates EC P-256 by default and P-384 on request", () => {
    expect(
      createPrivateKey(generateCertKeyPair({ algorithm: "ec" }).privateKeyPem).asymmetricKeyDetails
        ?.namedCurve,
    ).toBe("prime256v1");
    expect(
      createPrivateKey(generateCertKeyPair({ algorithm: "ec", namedCurve: "P-384" }).privateKeyPem)
        .asymmetricKeyDetails?.namedCurve,
    ).toBe("secp384r1");
  });
});
