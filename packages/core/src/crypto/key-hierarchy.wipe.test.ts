import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AAD_VAULT_KEK, AAD_WRAPPED_AUDIT_KEY, AAD_WRAPPED_JWT_KEY } from "@harpoc/shared";

// Capture every buffer the real decrypt returns, and allow forcing a failure
// on a specific AAD so we can drive the unwrap-failure path.
const decryptResults: { aad: string; result: Uint8Array }[] = [];
let throwOnAad: string | null = null;
const encryptInputs: { aad: string; plaintext: Uint8Array }[] = [];
let throwOnEncryptAad: string | null = null;
const derivedKeys: Uint8Array[] = [];
let deriveCalls = 0;
let failDeriveCall: number | null = null;

vi.mock("./aes-gcm.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./aes-gcm.js")>();
  return {
    ...original,
    encrypt: (key: Uint8Array, plaintext: Uint8Array, aad: string) => {
      encryptInputs.push({ aad, plaintext });
      if (throwOnEncryptAad !== null && aad === throwOnEncryptAad) {
        throw new Error("forced encrypt failure");
      }
      return original.encrypt(key, plaintext, aad);
    },
    decrypt: (
      key: Uint8Array,
      ciphertext: Uint8Array,
      iv: Uint8Array,
      tag: Uint8Array,
      aad: string,
    ): Uint8Array => {
      if (throwOnAad !== null && aad === throwOnAad) {
        throw new Error("forced decrypt failure");
      }
      const result = original.decrypt(key, ciphertext, iv, tag, aad);
      decryptResults.push({ aad, result });
      return result;
    },
  };
});

// Fast KDF — the wipe behavior under test is independent of the derivation cost.
vi.mock("./argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array): Promise<Uint8Array> => {
      deriveCalls += 1;
      if (deriveCalls === failDeriveCall) {
        throw new Error("forced derive failure");
      }
      const { createHash } = await import("node:crypto");
      const key = new Uint8Array(createHash("sha256").update(password).update(salt).digest());
      derivedKeys.push(key);
      return key;
    },
  };
});

const { changePassword, createVaultKeys, unlockVault } = await import("./key-hierarchy.js");

const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);

beforeEach(() => {
  decryptResults.length = 0;
  throwOnAad = null;
  encryptInputs.length = 0;
  throwOnEncryptAad = null;
  derivedKeys.length = 0;
  deriveCalls = 0;
  failDeriveCall = null;
});

afterEach(() => {
  throwOnAad = null;
  throwOnEncryptAad = null;
  failDeriveCall = null;
});

describe("unlockVault key-buffer wiping on unwrap failure", () => {
  it("wipes the derived KEK (and JWT key) when the audit-key unwrap throws", async () => {
    const keys = await createVaultKeys("password");

    throwOnAad = AAD_WRAPPED_AUDIT_KEY;

    await expect(
      unlockVault(
        "password",
        keys.salt,
        keys.wrappedKek,
        keys.wrappedKekIv,
        keys.wrappedKekTag,
        keys.wrappedJwtKey,
        keys.wrappedAuditKey,
      ),
    ).rejects.toThrow("forced decrypt failure");

    const kek = decryptResults.find((c) => c.aad === AAD_VAULT_KEK)?.result;
    const jwtKey = decryptResults.find((c) => c.aad === AAD_WRAPPED_JWT_KEY)?.result;

    expect(kek).toBeInstanceOf(Uint8Array);
    expect(jwtKey).toBeInstanceOf(Uint8Array);
    // Both intermediate keys derived before the failure must be zeroed, not
    // abandoned live in memory.
    expect(allZero(kek as Uint8Array)).toBe(true);
    expect(allZero(jwtKey as Uint8Array)).toBe(true);
  });

  it("wipes the KEK when the JWT-key unwrap throws (before the audit key exists)", async () => {
    const keys = await createVaultKeys("password");

    throwOnAad = AAD_WRAPPED_JWT_KEY;

    await expect(
      unlockVault(
        "password",
        keys.salt,
        keys.wrappedKek,
        keys.wrappedKekIv,
        keys.wrappedKekTag,
        keys.wrappedJwtKey,
        keys.wrappedAuditKey,
      ),
    ).rejects.toThrow("forced decrypt failure");

    const kek = decryptResults.find((c) => c.aad === AAD_VAULT_KEK)?.result;
    expect(kek).toBeInstanceOf(Uint8Array);
    expect(allZero(kek as Uint8Array)).toBe(true);
  });

  it("returns live keys on the success path (control)", async () => {
    const keys = await createVaultKeys("password");

    const unlocked = await unlockVault(
      "password",
      keys.salt,
      keys.wrappedKek,
      keys.wrappedKekIv,
      keys.wrappedKekTag,
      keys.wrappedJwtKey,
      keys.wrappedAuditKey,
    );

    // The returned KEK must NOT be zeroed — ownership passed to the caller.
    expect(allZero(unlocked.kek)).toBe(false);
    expect(unlocked.kek.length).toBe(32);
  });
});

describe("unlockVault master-key wiping", () => {
  it("wipes the master key after a successful unlock", async () => {
    const keys = await createVaultKeys("password");
    derivedKeys.length = 0;

    await unlockVault(
      "password",
      keys.salt,
      keys.wrappedKek,
      keys.wrappedKekIv,
      keys.wrappedKekTag,
      keys.wrappedJwtKey,
      keys.wrappedAuditKey,
    );

    expect(derivedKeys).toHaveLength(1);
    expect(allZero(derivedKeys[0] as Uint8Array)).toBe(true);
  });
});

describe("createVaultKeys key-buffer wiping on failure", () => {
  it.each([
    { key: "KEK", aad: AAD_VAULT_KEK },
    { key: "JWT key", aad: AAD_WRAPPED_JWT_KEY },
    { key: "audit key", aad: AAD_WRAPPED_AUDIT_KEY },
  ])("wipes the generated $key when the audit-key wrap throws", async ({ aad }) => {
    throwOnEncryptAad = AAD_WRAPPED_AUDIT_KEY;

    await expect(createVaultKeys("password")).rejects.toThrow("forced encrypt failure");

    const key = encryptInputs.find((c) => c.aad === aad)?.plaintext;
    expect(key).toBeInstanceOf(Uint8Array);
    expect(allZero(key as Uint8Array)).toBe(true);
  });
});

describe("changePassword key-buffer wiping", () => {
  async function changeFromFreshVault(): Promise<void> {
    const keys = await createVaultKeys("password");
    derivedKeys.length = 0;
    await changePassword(
      "password",
      "new-password",
      keys.salt,
      keys.wrappedKek,
      keys.wrappedKekIv,
      keys.wrappedKekTag,
    );
  }

  it("wipes the old master key once the KEK is unwrapped", async () => {
    await changeFromFreshVault();

    expect(derivedKeys).toHaveLength(2);
    expect(allZero(derivedKeys[0] as Uint8Array)).toBe(true);
  });

  it("wipes the new master key once the KEK is re-wrapped", async () => {
    await changeFromFreshVault();

    expect(derivedKeys).toHaveLength(2);
    expect(allZero(derivedKeys[1] as Uint8Array)).toBe(true);
  });

  it("wipes the unwrapped KEK when the new-master-key derivation throws", async () => {
    const keys = await createVaultKeys("password");
    failDeriveCall = deriveCalls + 2;

    await expect(
      changePassword(
        "password",
        "new-password",
        keys.salt,
        keys.wrappedKek,
        keys.wrappedKekIv,
        keys.wrappedKekTag,
      ),
    ).rejects.toThrow("forced derive failure");

    const kek = decryptResults.find((c) => c.aad === AAD_VAULT_KEK)?.result;
    expect(kek).toBeInstanceOf(Uint8Array);
    expect(allZero(kek as Uint8Array)).toBe(true);
  });
});
