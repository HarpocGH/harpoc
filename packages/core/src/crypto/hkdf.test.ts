import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AES_KEY_LENGTH } from "@harpoc/shared";
import { deriveSubkey } from "./hkdf.js";

const ikm = new Uint8Array(randomBytes(32));
const salt = "test-vault-id";
const INFO_A = "test-info-a";
const INFO_B = "test-info-b";

describe("deriveSubkey", () => {
  it("returns 32 bytes by default", async () => {
    const key = await deriveSubkey(ikm, salt, INFO_A);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(AES_KEY_LENGTH);
  });

  it("returns custom length when specified", async () => {
    const key = await deriveSubkey(ikm, salt, INFO_A, 64);
    expect(key.length).toBe(64);
  });

  it("is deterministic for same inputs", async () => {
    const k1 = await deriveSubkey(ikm, salt, INFO_A);
    const k2 = await deriveSubkey(ikm, salt, INFO_A);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
  });

  it("produces different keys for different info strings", async () => {
    const k1 = await deriveSubkey(ikm, salt, INFO_A);
    const k2 = await deriveSubkey(ikm, salt, INFO_B);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("produces different keys for different salts", async () => {
    const k1 = await deriveSubkey(ikm, "vault-1", INFO_A);
    const k2 = await deriveSubkey(ikm, "vault-2", INFO_A);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("produces different keys for different IKM", async () => {
    const ikm2 = new Uint8Array(randomBytes(32));
    const k1 = await deriveSubkey(ikm, salt, INFO_A);
    const k2 = await deriveSubkey(ikm2, salt, INFO_A);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });
});
