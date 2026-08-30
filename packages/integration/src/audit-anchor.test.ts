import { copyFileSync, existsSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "@harpoc/core";
import type { AuditChainAnchor } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { dropAuditRowHmacConstraint } from "@harpoc/test-utils";

const PASSWORD = "integration-password";

let vault: TestVault;

beforeEach(async () => {
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
});

afterEach(async () => {
  await destroyTestVault(vault);
});

async function createSecrets(names: string[]): Promise<void> {
  for (const name of names) {
    await vault.engine.createSecret({
      name,
      type: "api_key",
      value: new Uint8Array(Buffer.from(`value-${name}`)),
    });
  }
}

/** Attacker with direct DB write access (no audit key): delete the newest rows. */
function truncateTail(fromId: number): void {
  const store = new SqliteStore(vault.dbPath);
  try {
    store.db.prepare("DELETE FROM audit_log WHERE id >= ?").run(fromId);
  } finally {
    store.close();
  }
}

/** Same attacker, erasing the chain links instead of the rows (M2). */
function nullLinks(fromId: number): void {
  const store = new SqliteStore(vault.dbPath);
  try {
    dropAuditRowHmacConstraint(store.db);
    store.db.prepare("UPDATE audit_log SET row_hmac = NULL WHERE id >= ?").run(fromId);
  } finally {
    store.close();
  }
}

const DB_SIDECARS = ["", "-wal", "-shm"];

function snapshotDb(dir: string): void {
  for (const suffix of DB_SIDECARS) {
    if (existsSync(vault.dbPath + suffix))
      copyFileSync(vault.dbPath + suffix, join(dir, `db${suffix}`));
  }
}

function restoreDb(dir: string): void {
  for (const suffix of DB_SIDECARS) {
    if (existsSync(vault.dbPath + suffix)) unlinkSync(vault.dbPath + suffix);
    if (existsSync(join(dir, `db${suffix}`)))
      copyFileSync(join(dir, `db${suffix}`), vault.dbPath + suffix);
  }
}

describe("audit-chain anchor across the real database file", () => {
  it("detects tail truncation the chain HMACs alone cannot see", async () => {
    await createSecrets(["alpha", "beta", "gamma"]);
    const anchor = vault.engine.getAuditChainTail() as AuditChainAnchor;
    expect(anchor).not.toBeNull();

    await createSecrets(["delta", "epsilon"]);
    const later = vault.engine.getAuditChainTail() as AuditChainAnchor;
    expect(later.last_id).toBeGreaterThan(anchor.last_id);

    // A pre-truncation check passes against both anchors.
    expect(vault.engine.verifyAuditChain({ anchor }).valid).toBe(true);
    expect(vault.engine.verifyAuditChain({ anchor: later }).valid).toBe(true);

    // Attacker deletes everything after the first anchor — later's rows vanish.
    truncateTail(anchor.last_id + 1);

    // The pinned vulnerability: the shortened chain still verifies clean.
    const plain = vault.engine.verifyAuditChain();
    expect(plain.valid).toBe(true);

    // The old anchor still holds (its row survived)…
    expect(vault.engine.verifyAuditChain({ anchor }).valid).toBe(true);

    // …but the operator's newest anchor catches the truncation.
    const detected = vault.engine.verifyAuditChain({ anchor: later });
    expect(detected.valid).toBe(false);
    expect(detected.anchor).toEqual({ lastId: later.last_id, status: "row_missing" });
  });

  // M2: the same DB-write attacker can also erase the LINKS instead of the
  // rows. Nulling row_hmac made rows read as pre-migration legacy, which
  // verification skipped — so the suffix could then be rewritten at will and
  // `harpoc audit verify` still exited 0. No anchor is needed to catch this.
  // Since R2 the column is NOT NULL, so the attacker first rebuilds the table
  // without it (nullLinks does), and the last test pins that the shipped table
  // refuses the plain UPDATE.
  it("detects erased chain links without any anchor", async () => {
    await createSecrets(["alpha", "beta", "gamma"]);
    const anchor = vault.engine.getAuditChainTail() as AuditChainAnchor;
    expect(vault.engine.verifyAuditChain().valid).toBe(true);

    await createSecrets(["delta"]);
    nullLinks(anchor.last_id + 1);

    const plain = vault.engine.verifyAuditChain();
    expect(plain.valid).toBe(false);
    expect(plain.firstBrokenId).toBe(anchor.last_id + 1);
  });

  it("detects a wholly erased chain", async () => {
    await createSecrets(["alpha", "beta"]);
    nullLinks(0);

    const plain = vault.engine.verifyAuditChain();
    expect(plain.valid).toBe(false);
    expect(plain.checked).toBe(0);
  });

  it("a fresh anchor keeps verifying as rows are appended", async () => {
    await createSecrets(["one"]);
    const anchor = vault.engine.getAuditChainTail() as AuditChainAnchor;

    await createSecrets(["two", "three"]);
    const result = vault.engine.verifyAuditChain({ anchor });
    expect(result.valid).toBe(true);
    expect(result.anchor?.status).toBe("ok");
    expect(result.tail?.last_id).toBeGreaterThan(anchor.last_id);
  });

  it("detects a database rollback via the operator's newest anchor", async () => {
    await createSecrets(["pre-snapshot"]);
    const anchorEarly = vault.engine.getAuditChainTail() as AuditChainAnchor;

    // Close the vault's handle so the snapshot/restore is byte-faithful.
    const snapshotDir = mkdtempSync(join(tmpdir(), "harpoc-anchor-snap-"));
    try {
      await vault.engine.destroy();
      snapshotDb(snapshotDir);

      // Keep using the vault after the snapshot.
      vault.engine = createTestVault(vault.tmpDir).engine;
      await vault.engine.unlock(PASSWORD);
      await createSecrets(["post-snapshot-1", "post-snapshot-2"]);
      const anchorLate = vault.engine.getAuditChainTail() as AuditChainAnchor;
      expect(anchorLate.last_id).toBeGreaterThan(anchorEarly.last_id);

      // Attacker restores the older database copy.
      await vault.engine.destroy();
      restoreDb(snapshotDir);
      vault.engine = createTestVault(vault.tmpDir).engine;
      await vault.engine.unlock(PASSWORD);

      // The chain itself is clean, and the early anchor legitimately matches
      // the restored state — a rollback to the anchor point is undetectable
      // by that anchor alone.
      expect(vault.engine.verifyAuditChain().valid).toBe(true);

      // The operator's NEWEST anchor is the detection story: its row is gone.
      const detected = vault.engine.verifyAuditChain({ anchor: anchorLate });
      expect(detected.valid).toBe(false);
      expect(detected.anchor?.status).toBe("row_missing");
    } finally {
      rmSync(snapshotDir, { recursive: true, force: true });
    }
  });

  it("rejects an anchor from a different vault", async () => {
    await createSecrets(["mine"]);
    const anchor = vault.engine.getAuditChainTail() as AuditChainAnchor;

    const foreignVault = createTestVault();
    try {
      await foreignVault.engine.initVault(PASSWORD);
      expect(() => foreignVault.engine.verifyAuditChain({ anchor })).toThrowError(
        /different vault/,
      );
    } finally {
      await destroyTestVault(foreignVault);
    }
  });

  it("the v1.5 table refuses an erased link outright (R2)", async () => {
    await createSecrets(["alpha"]);
    const store = new SqliteStore(vault.dbPath);
    let caught: unknown;
    try {
      store.db.prepare("UPDATE audit_log SET row_hmac = NULL").run();
    } catch (err) {
      caught = err;
    } finally {
      store.close();
    }
    expect((caught as { code?: string } | undefined)?.code).toBe("SQLITE_CONSTRAINT_NOTNULL");
    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });
});
