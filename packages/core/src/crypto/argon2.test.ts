import { describe, expect, it } from "vitest";
import { ARGON2_HASH_LENGTH } from "@harpoc/shared";
import { deriveKey, generateSalt } from "./argon2.js";

describe("generateSalt", () => {
  it("returns 16 bytes", () => {
    const salt = generateSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.length).toBe(16);
  });

  it("generates unique salts", () => {
    const s1 = generateSalt();
    const s2 = generateSalt();
    expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(false);
  });
});

describe("deriveKey", () => {
  it("returns a 32-byte key", async () => {
    const salt = generateSalt();
    const key = await deriveKey("test-password", salt);

    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(ARGON2_HASH_LENGTH);
  });

  it("is deterministic for same password and salt", async () => {
    const salt = generateSalt();
    const k1 = await deriveKey("password", salt);
    const k2 = await deriveKey("password", salt);

    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
  });

  it("produces different keys for different passwords", async () => {
    const salt = generateSalt();
    const k1 = await deriveKey("password1", salt);
    const k2 = await deriveKey("password2", salt);

    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("produces different keys for different salts", async () => {
    const s1 = generateSalt();
    const s2 = generateSalt();
    const k1 = await deriveKey("password", s1);
    const k2 = await deriveKey("password", s2);

    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("handles empty password", async () => {
    const salt = generateSalt();
    const key = await deriveKey("", salt);
    expect(key.length).toBe(ARGON2_HASH_LENGTH);
  });

  it("handles unicode password", async () => {
    const salt = generateSalt();
    const key = await deriveKey("p\u00e4ssw\u00f6rd\ud83d\udd12", salt);
    expect(key.length).toBe(ARGON2_HASH_LENGTH);
  });
});

describe("deriveKey known-answer (drift tripwire)", () => {
  it("matches the pinned Argon2id output for fixed password + salt", async () => {
    // Computed with the production parameters (argon2id, 64 MiB, t=3, p=4,
    // v1.3, 32 bytes). Any parameter or algorithm drift changes this value.
    const salt = new Uint8Array(16).fill(0xa5);
    const key = await deriveKey("harpoc-kat-password", salt);
    expect(Buffer.from(key).toString("hex")).toBe(
      "f828258bca45d7f572c6d407d3a6a579526298fdceb04062487378e3f4aa535e",
    );
  });
});
