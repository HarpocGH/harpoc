import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { expectVaultError } from "@harpoc/test-utils";

const PASSWORD = "pre-baseline-vault-pw";

interface SqliteHandle {
  exec(sql: string): void;
  prepare(sql: string): { get(...params: unknown[]): unknown };
}

/** The engine's own connection: one handle on the file, better-sqlite3 stays out of this package. */
function borrowDb(vault: TestVault): SqliteHandle {
  return (vault.engine as unknown as { store: { db: SqliteHandle } }).store.db;
}

/**
 * A v1.4 vault file — the v1.2/v1.3/v1.4 line's last schema, 11 — against the
 * v1.5 runner (R2): the two v1.4 tables and the audit principal index dropped,
 * `schema_version` set back to 11, and a fresh engine asked to open it. The
 * ladder that used to upgrade it is gone; the open refuses before any DDL,
 * naming the remedy, and leaves the file exactly as it found it.
 */
describe("a pre-baseline vault file is refused, not upgraded (R2)", () => {
  let vaultDir = "";
  let refused: TestVault;

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-prebase-"));

    const original = createTestVault(vaultDir);
    await original.engine.initVault(PASSWORD);
    original.engine.registerAgent({ name: "legacy-bot" });
    await original.engine.createSecret({
      name: "legacy-secret",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("legacy-value")),
    });
    const secretId = await original.engine.resolveSecretId("secret://legacy-secret");
    original.engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "legacy-bot", permissions: ["read"] },
      "integration-test",
    );

    borrowDb(original).exec(
      [
        "DROP TABLE issued_tokens;",
        "DROP TABLE agents;",
        "DROP INDEX idx_audit_principal;",
        "UPDATE vault_meta SET value = '11' WHERE key = 'schema_version';",
      ].join("\n"),
    );
    await original.engine.destroy();

    refused = createTestVault(vaultDir);
  });

  afterAll(async () => {
    await destroyTestVault(refused).catch(() => {});
    if (vaultDir !== "") rmSync(vaultDir, { recursive: true, force: true });
  });

  it("refuses unlock as VAULT_CORRUPTED naming the schema, the baseline and harpoc init", async () => {
    const err = await expectVaultError(
      () => refused.engine.unlock(PASSWORD),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(err.message).toBe(
      "Vault corrupted: Vault schema 11 predates the v1.5 baseline (12) and cannot be upgraded — move or delete the vault directory and run harpoc init",
    );
  });

  it("refuses identically on a second attempt — the refusal runs before any DDL", async () => {
    await expectVaultError(() => refused.engine.unlock(PASSWORD), ErrorCode.VAULT_CORRUPTED);
    const again = createTestVault(vaultDir);
    try {
      const err = await expectVaultError(
        () => again.engine.unlock(PASSWORD),
        ErrorCode.VAULT_CORRUPTED,
      );
      expect(err.message).toContain("Vault schema 11");
    } finally {
      await again.engine.destroy();
    }
  });
});
