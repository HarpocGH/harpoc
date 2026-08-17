import { describe, expect, it } from "vitest";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { generateCertKeyPair } from "./key-pair.js";

describe("generateCertKeyPair", () => {
  it("generates RSA 2048 PEM pairs", () => {
    const { privateKeyPem, publicKeyPem } = generateCertKeyPair({ algorithm: "rsa" });
    const key = createPrivateKey(privateKeyPem);
    expect(key.asymmetricKeyType).toBe("rsa");
    expect(createPublicKey(publicKeyPem).asymmetricKeyType).toBe("rsa");
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
