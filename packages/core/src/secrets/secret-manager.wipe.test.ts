import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Capture every DEK-sized buffer generateRandomBytes hands out so we can prove
// it is zeroed even when a later step throws.
const generatedBuffers: Uint8Array[] = [];
const unwrappedDeks: Uint8Array[] = [];

vi.mock("../crypto/random.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../crypto/random.js")>();
  return {
    ...original,
    generateRandomBytes: (length: number): Uint8Array => {
      const buf = original.generateRandomBytes(length);
      generatedBuffers.push(buf);
      return buf;
    },
  };
});

// Force the DEK wrap to throw, exercising the createSecret failure path, or
// the value encryption, exercising the rotateSecret failure path.
let wrapShouldThrow = false;
let encryptValueShouldThrow = false;
vi.mock("../crypto/key-hierarchy.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../crypto/key-hierarchy.js")>();
  return {
    ...original,
    wrapDek: (kek: Uint8Array, dek: Uint8Array, secretId: string) => {
      if (wrapShouldThrow) {
        throw new Error("forced wrap failure");
      }
      return original.wrapDek(kek, dek, secretId);
    },
    unwrapDek: (...args: Parameters<typeof original.unwrapDek>) => {
      const dek = original.unwrapDek(...args);
      unwrappedDeks.push(dek);
      return dek;
    },
    encryptSecretValue: (...args: Parameters<typeof original.encryptSecretValue>) => {
      if (encryptValueShouldThrow) {
        throw new Error("forced value encryption failure");
      }
      return original.encryptSecretValue(...args);
    },
  };
});

const { createVaultKeys } = await import("../crypto/key-hierarchy.js");
const { SqliteStore } = await import("../storage/sqlite-store.js");
const { SecretManager } = await import("./secret-manager.js");

let store: InstanceType<typeof SqliteStore>;
let manager: InstanceType<typeof SecretManager>;

beforeEach(async () => {
  wrapShouldThrow = false;
  encryptValueShouldThrow = false;
  const keys = await createVaultKeys("test-password");
  store = new SqliteStore(":memory:");
  manager = new SecretManager(store, keys.kek);
  // Discard the vault-key buffers created above (they are live, not wiped);
  // only DEKs generated during the test itself are under assertion.
  generatedBuffers.length = 0;
  unwrappedDeks.length = 0;
});

afterEach(() => {
  store.close();
});

describe("createSecret DEK wiping on failure", () => {
  it("wipes the plaintext DEK when wrapDek throws", async () => {
    wrapShouldThrow = true;

    await expect(
      manager.createSecret({
        name: "will-fail",
        type: "api_key",
        value: new Uint8Array(Buffer.from("secret-value")),
      }),
    ).rejects.toThrow("forced wrap failure");

    // The DEK is the one 32-byte buffer generateRandomBytes produced during
    // createSecret; it must be zeroed despite the throw.
    const deks = generatedBuffers.filter((b) => b.length === 32);
    expect(deks.length).toBeGreaterThanOrEqual(1);
    for (const dek of deks) {
      expect(dek.every((b) => b === 0)).toBe(true);
    }

    // No row was inserted.
    expect(manager.listSecrets()).toHaveLength(0);
  });

  it("wipes the DEK on the success path too (control)", async () => {
    await manager.createSecret({
      name: "ok",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const deks = generatedBuffers.filter((b) => b.length === 32);
    expect(deks.length).toBeGreaterThanOrEqual(1);
    for (const dek of deks) {
      expect(dek.every((b) => b === 0)).toBe(true);
    }
  });
});

describe("DEK wiping after rotate, read and pending-value write", () => {
  it("rotateSecret wipes the new DEK when the value encryption throws", async () => {
    await manager.createSecret({
      name: "rotate-fail",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });
    generatedBuffers.length = 0;
    encryptValueShouldThrow = true;

    await expect(
      manager.rotateSecret("secret://rotate-fail", new Uint8Array(Buffer.from("v2"))),
    ).rejects.toThrow("forced value encryption failure");

    const deks = generatedBuffers.filter((b) => b.length === 32);
    expect(deks).toHaveLength(1);
    expect((deks[0] as Uint8Array).every((b) => b === 0)).toBe(true);
  });

  it("getSecretValue wipes the unwrapped DEK after the decrypt", async () => {
    await manager.createSecret({
      name: "read-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await manager.getSecretValue("secret://read-me");

    expect(unwrappedDeks).toHaveLength(1);
    expect((unwrappedDeks[0] as Uint8Array).every((b) => b === 0)).toBe(true);
  });

  it("setSecretValue wipes the unwrapped DEK after the encrypt", async () => {
    await manager.createSecret({ name: "pending-one", type: "api_key" });

    await manager.setSecretValue("secret://pending-one", new Uint8Array(Buffer.from("v")));

    expect(unwrappedDeks).toHaveLength(1);
    expect((unwrappedDeks[0] as Uint8Array).every((b) => b === 0)).toBe(true);
  });
});
