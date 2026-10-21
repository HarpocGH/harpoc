import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VaultState } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import type { VaultEngineOptions } from "./vault-engine.js";
import { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const INJECTED = new Error("injected setMeta failure");

let tempDir: string;
let options: VaultEngineOptions;
const engines: VaultEngine[] = [];

function openEngine(): VaultEngine {
  const engine = new VaultEngine(options);
  engines.push(engine);
  return engine;
}

function failOnMetaKey(key: string): void {
  const original = SqliteStore.prototype.setMeta;
  vi.spyOn(SqliteStore.prototype, "setMeta").mockImplementation(function (
    this: SqliteStore,
    metaKey: string,
    value: string,
  ) {
    if (metaKey === key) throw INJECTED;
    original.call(this, metaKey, value);
  });
}

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-init-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  options = { dbPath: join(tempDir, "test.vault.db"), sessionPath: join(tempDir, "session.json") };
});

afterEach(async () => {
  vi.restoreAllMocks();
  for (const engine of engines.splice(0)) await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("initVault commits its metadata in one transaction (B4)", () => {
  it("a write failing after vault_id leaves no vault metadata behind", async () => {
    failOnMetaKey("wrapped_kek_iv");

    await expect(openEngine().initVault("password")).rejects.toBe(INJECTED);
    vi.restoreAllMocks();

    const store = new SqliteStore(options.dbPath);
    try {
      expect(store.getMeta("vault_id")).toBeUndefined();
      expect(store.getMeta("vault_version")).toBeUndefined();
      expect(store.getMeta("kdf_salt")).toBeUndefined();
      expect(store.getMeta("wrapped_kek")).toBeUndefined();
    } finally {
      store.close();
    }
  });

  it("a failed initialization can be retried on the same path and the vault then unlocks", async () => {
    failOnMetaKey("wrapped_audit_key_tag");
    await expect(openEngine().initVault("password")).rejects.toBe(INJECTED);
    vi.restoreAllMocks();

    const retry = openEngine();
    const { vaultId } = await retry.initVault("password");
    await retry.lock();

    const reopened = openEngine();
    await reopened.unlock("password");
    expect(reopened.getState()).toBe(VaultState.UNLOCKED);
    const store = new SqliteStore(options.dbPath);
    try {
      expect(store.getMeta("vault_id")).toBe(vaultId);
    } finally {
      store.close();
    }
  });

  it("the failed call closes the store it opened and leaves the engine sealed", async () => {
    const close = vi.spyOn(SqliteStore.prototype, "close");
    failOnMetaKey("wrapped_kek_tag");
    const engine = openEngine();

    await expect(engine.initVault("password")).rejects.toBe(INJECTED);

    expect(close).toHaveBeenCalledTimes(1);
    expect(engine.getState()).toBe(VaultState.SEALED);
  });
});
