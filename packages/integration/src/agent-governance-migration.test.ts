import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AgentStatus, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const PASSWORD = "agent-governance-migration-pw";
const BACKFILL_DESCRIPTION = "auto-registered from existing grants (migration 012)";

interface SqliteHandle {
  exec(sql: string): void;
  prepare(sql: string): { get(...params: unknown[]): unknown };
}

/**
 * The engine's own connection, the idiom of `security-oauth-certs.test.ts`:
 * one handle on the file, and `better-sqlite3` stays out of this package's
 * dependencies.
 */
function borrowDb(vault: TestVault): SqliteHandle {
  return (vault.engine as unknown as { store: { db: SqliteHandle } }).store.db;
}

/**
 * Migration 012 against a real vault file rather than a hand-built fixture:
 * a v12 vault is downgraded in place — the two v1.4 tables and the audit
 * principal index dropped, `schema_version` set back to 11 — and re-opened
 * with a fresh engine, so the ladder re-runs and the backfill registers the
 * agent principals that already hold grants. The tables are dropped rather
 * than only the version rewound: `CREATE TABLE IF NOT EXISTS` would skip and
 * the backfill's `INSERT OR IGNORE` would no-op on the surviving row, leaving
 * the test green without the backfill ever running. The migration description
 * is what proves it did.
 */
describe("migration 012 agent backfill on a real vault file", () => {
  let vaultDir = "";
  let upgraded: TestVault;

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-agov-"));

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
    original.engine.grantPolicy(
      { secretId, principalType: "tool", principalId: "legacy-tool", permissions: ["read"] },
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

    upgraded = createTestVault(vaultDir);
    await upgraded.engine.unlock(PASSWORD);
  });

  afterAll(async () => {
    await destroyTestVault(upgraded).catch(() => {});
    // A failure before `upgraded` is assigned leaves the directory behind:
    // `destroyTestVault` never reaches its own cleanup, so remove it here too.
    if (vaultDir !== "") rmSync(vaultDir, { recursive: true, force: true });
  });

  it("registers the agent principals that already held grants", () => {
    const agents = upgraded.engine.listAgents("all");
    const names = agents.map((agent) => agent.name);

    expect(names).toContain("legacy-bot");
    expect(names).not.toContain("legacy-tool");

    const backfilled = agents.find((agent) => agent.name === "legacy-bot");
    expect(backfilled?.status).toBe(AgentStatus.ACTIVE);
    expect(backfilled?.description).toBe(BACKFILL_DESCRIPTION);
    expect(backfilled?.owner).toBeNull();
    expect(backfilled?.deactivated_at).toBeNull();
  });

  it("keeps the grants the backfill was read from", () => {
    const policies = upgraded.engine.listAgentPolicies("legacy-bot");
    expect(policies).toHaveLength(1);
    expect(policies[0]?.handle).toBe("secret://legacy-secret");
    expect(policies[0]?.permissions).toEqual(["read"]);
  });

  it("mints a token for the backfilled agent through the registration gate", () => {
    const token = upgraded.engine.createToken("legacy-bot", ["use"]);
    expect(token.split(".")).toHaveLength(3);

    const rows = upgraded.engine.listIssuedTokens({ agent: "legacy-bot", status: "all" });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.subject).toBe("legacy-bot");
    expect(rows[0]?.agent).toBe("legacy-bot");
  });

  it("stamps the schema version back to 12", () => {
    const row = borrowDb(upgraded)
      .prepare("SELECT value FROM vault_meta WHERE key = 'schema_version'")
      .get() as { value: string } | undefined;
    expect(row?.value).toBe("12");
  });

  it("leaves the audit chain verifiable across the downgrade and re-upgrade", () => {
    expect(upgraded.engine.verifyAuditChain().valid).toBe(true);
  });
});
