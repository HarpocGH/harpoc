import { randomUUID } from "node:crypto";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { computeNameHmac, createVaultKeys } from "../crypto/key-hierarchy.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { SecretManager } from "./secret-manager.js";

let kek: Uint8Array;

beforeAll(async () => {
  const keys = await createVaultKeys("test-password");
  kek = keys.kek;
});

describe("createSecret duplicate handling (TOCTOU fix)", () => {
  let store: SqliteStore;
  let manager: SecretManager;

  beforeEach(() => {
    store = new SqliteStore(":memory:");
    manager = new SecretManager(store, kek);
  });

  afterEach(() => {
    store.close();
  });

  it("rejects a second concurrent create of the same name with DUPLICATE_SECRET (one row)", async () => {
    const create = (): Promise<unknown> =>
      manager.createSecret({
        name: "race",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v")),
      });

    const results = await Promise.allSettled([create(), create()]);
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({
      code: ErrorCode.DUPLICATE_SECRET,
    });
    expect(store.getSecretsByNameHmac(await computeNameHmac(kek, "race", null))).toHaveLength(1);
  });

  it("allows recreating a name after the original is revoked", async () => {
    await manager.createSecret({
      name: "reusable",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });
    await manager.revokeSecret("secret://reusable");

    await expect(
      manager.createSecret({
        name: "reusable",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).resolves.toMatchObject({ status: "created" });
  });

  it("still blocks recreating a name held by an expired secret", async () => {
    await manager.createSecret({
      name: "soon",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000, // already expired (still non-revoked)
    });

    await expect(
      manager.createSecret({
        name: "soon",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.DUPLICATE_SECRET });
  });

  it("enforces the unique index at the storage layer (cross-process backstop)", async () => {
    const hmac = await computeNameHmac(kek, "pinned", null);
    const row = (status: string) => ({
      id: randomUUID(),
      name_encrypted: new Uint8Array([1]),
      name_iv: new Uint8Array([1]),
      name_tag: new Uint8Array([1]),
      type: "api_key" as const,
      project: null,
      wrapped_dek: new Uint8Array([1]),
      dek_iv: new Uint8Array([1]),
      dek_tag: new Uint8Array([1]),
      ciphertext: new Uint8Array([1]),
      ct_iv: new Uint8Array([1]),
      ct_tag: new Uint8Array([1]),
      metadata_encrypted: null,
      metadata_iv: null,
      metadata_tag: null,
      created_at: Date.now(),
      updated_at: Date.now(),
      expires_at: null,
      rotated_at: null,
      version: 1,
      status: status as "active",
      name_hmac: hmac,
    });

    store.insertSecret(row("active"));
    // Second live row with the same name_hmac violates the partial unique index.
    expect(() => store.insertSecret(row("active"))).toThrow();
    // A revoked row with the same name_hmac is allowed (excluded from the index).
    expect(() => store.insertSecret(row("revoked"))).not.toThrow();
  });
});
