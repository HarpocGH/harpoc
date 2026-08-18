import { describe, expect, it } from "vitest";

import { isEncryptedPrivateKeyPem } from "./pem.js";

describe("isEncryptedPrivateKeyPem", () => {
  it("detects a PKCS#8 encrypted private key", () => {
    const pem =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE...\n-----END ENCRYPTED PRIVATE KEY-----";
    expect(isEncryptedPrivateKeyPem(pem)).toBe(true);
  });

  it("detects a legacy PEM with a Proc-Type: 4,ENCRYPTED header", () => {
    const pem =
      "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,...\n\nMIIE...\n-----END RSA PRIVATE KEY-----";
    expect(isEncryptedPrivateKeyPem(pem)).toBe(true);
  });

  it("returns false for a plain unencrypted private key", () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----";
    expect(isEncryptedPrivateKeyPem(pem)).toBe(false);
  });

  it("returns false for a certificate", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----";
    expect(isEncryptedPrivateKeyPem(pem)).toBe(false);
  });
});
