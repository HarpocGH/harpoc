import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode, VAULT_DB_NAME, VAULT_DIR_NAME, VaultError } from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";
import { createEngine, loadUnlockedEngine, resolveSecretId, resolveVaultDir } from "./vault-loader.js";

let tempDir: string;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-vl-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
});

afterEach(() => {
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("resolveVaultDir", () => {
  it("returns explicit path when provided", () => {
    const explicit = join(tempDir, "custom-vault");
    expect(resolveVaultDir(explicit)).toBe(explicit);
  });

  it("falls back to home directory vault when cwd has no .harpoc", () => {
    const result = resolveVaultDir();
    expect(result).toContain(VAULT_DIR_NAME);
  });
});

describe("createEngine", () => {
  it("returns a VaultEngine instance", () => {
    const engine = createEngine(tempDir);
    expect(engine).toBeInstanceOf(VaultEngine);
  });
});

describe("loadUnlockedEngine", () => {
  it("returns unlocked engine when session is active", async () => {
    // First init a vault to create a valid session
    const dbPath = join(tempDir, VAULT_DB_NAME);
    const sessionPath = join(tempDir, "session.json");
    const setupEngine = new VaultEngine({ dbPath, sessionPath });
    await setupEngine.initVault("test-password");
    await setupEngine.destroy();

    // Now load via the utility
    const engine = await loadUnlockedEngine(tempDir);
    expect(engine.getState()).toBe("unlocked");
    await engine.destroy();
  });

  it("throws VAULT_LOCKED when no valid session exists", async () => {
    // Create vault but lock it (erases session)
    const dbPath = join(tempDir, VAULT_DB_NAME);
    const sessionPath = join(tempDir, "session.json");
    const setupEngine = new VaultEngine({ dbPath, sessionPath });
    await setupEngine.initVault("test-password");
    await setupEngine.lock();
    await setupEngine.destroy();

    try {
      await loadUnlockedEngine(tempDir);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });
});

describe("resolveSecretId", () => {
  it("returns the internal UUID for a valid handle", async () => {
    const dbPath = join(tempDir, VAULT_DB_NAME);
    const sessionPath = join(tempDir, "session.json");
    const engine = new VaultEngine({ dbPath, sessionPath });
    await engine.initVault("test-password");

    await engine.createSecret({
      name: "my-secret",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    const id = await resolveSecretId(engine, "secret://my-secret");
    // UUID format: 8-4-4-4-12
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    await engine.destroy();
  });

  it("throws when vault is not unlocked", async () => {
    const dbPath = join(tempDir, VAULT_DB_NAME);
    const sessionPath = join(tempDir, "session.json");
    const engine = new VaultEngine({ dbPath, sessionPath });

    await expect(resolveSecretId(engine, "secret://any")).rejects.toThrow();
  });
});
