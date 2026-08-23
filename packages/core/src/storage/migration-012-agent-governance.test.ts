import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStore } from "./sqlite-store.js";
import { migration001 } from "./migrations/001-initial.js";
import { migration002 } from "./migrations/002-revoked-tokens.js";
import { migration003 } from "./migrations/003-name-hmac.js";
import { migration004 } from "./migrations/004-oauth-tokens.js";
import { migration005 } from "./migrations/005-certificates.js";
import { migration006 } from "./migrations/006-injection-policies.js";
import { migration007 } from "./migrations/007-mcp-servers.js";
import { migration008 } from "./migrations/008-connection-configs.js";
import { migration009 } from "./migrations/009-name-hmac-unique.js";
import { migration010 } from "./migrations/010-audit-row-hmac.js";
import { migration011 } from "./migrations/011-oauth-auth-method.js";

const BACKFILL_DESCRIPTION = "auto-registered from existing grants (migration 012)";

interface AgentTableRow {
  id: string;
  name: string;
  description: string | null;
  owner: string | null;
  status: string;
  created_at: number;
  updated_at: number;
  deactivated_at: number | null;
}

describe("migration 012 upgrade (v11 → v12)", () => {
  let tempDir: string;

  /** Build a v11 vault carrying one secret plus the given access_policies principals. */
  const buildV11Db = (dbPath: string, principals: Array<[string, string]>): void => {
    const db = new Database(dbPath);
    db.pragma("foreign_keys = ON");
    for (const m of [
      migration001,
      migration002,
      migration003,
      migration004,
      migration005,
      migration006,
      migration007,
      migration008,
      migration009,
      migration010,
      migration011,
    ]) {
      db.exec(m.up);
    }
    db.prepare(
      "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', '11')",
    ).run();

    const secretId = randomUUID();
    db.prepare(
      `INSERT INTO secrets (
        id, name_encrypted, name_iv, name_tag, type, project,
        wrapped_dek, dek_iv, dek_tag, ciphertext, ct_iv, ct_tag,
        created_at, updated_at, version, status, sync_version, name_hmac
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      secretId,
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      "api_key",
      null,
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Buffer.from([1]),
      Date.now(),
      Date.now(),
      1,
      "active",
      0,
      "legacy-secret",
    );

    const insertPolicy = db.prepare(
      `INSERT INTO access_policies (
        id, secret_id, principal_type, principal_id, permissions,
        created_at, expires_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const [principalType, principalId] of principals) {
      insertPolicy.run(
        randomUUID(),
        secretId,
        principalType,
        principalId,
        JSON.stringify(["read"]),
        Date.now(),
        null,
        "user",
      );
    }
    db.close();
  };

  const readAgents = (store: SqliteStore): AgentTableRow[] =>
    store.db.prepare("SELECT * FROM agents ORDER BY name ASC").all() as AgentTableRow[];

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "harpoc-mig012-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("backfills one agent per distinct agent principal and skips non-agent principals", () => {
    const dbPath = join(tempDir, "backfill.vault.db");
    buildV11Db(dbPath, [
      ["agent", "alpha"],
      ["agent", "beta"],
      ["agent", "alpha"],
      ["tool", "builder"],
    ]);

    const store = new SqliteStore(dbPath);
    expect(store.getMeta("schema_version")).toBe("12");

    const agents = readAgents(store);
    expect(agents.map((a) => a.name)).toEqual(["alpha", "beta"]);
    for (const agent of agents) {
      expect(agent.status).toBe("active");
      expect(agent.description).toBe(BACKFILL_DESCRIPTION);
      expect(agent.owner).toBeNull();
      expect(agent.deactivated_at).toBeNull();
      expect(agent.created_at).toBeGreaterThan(0);
      expect(agent.updated_at).toBe(agent.created_at);
      expect(agent.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-/);
    }
    store.close();
  });

  it("is idempotent — reopening the upgraded file does not duplicate agents", () => {
    const dbPath = join(tempDir, "idempotent.vault.db");
    buildV11Db(dbPath, [
      ["agent", "alpha"],
      ["agent", "beta"],
    ]);

    const first = new SqliteStore(dbPath);
    const firstIds = readAgents(first).map((a) => a.id);
    first.close();

    const second = new SqliteStore(dbPath);
    const secondAgents = readAgents(second);
    expect(secondAgents.map((a) => a.name)).toEqual(["alpha", "beta"]);
    expect(secondAgents.map((a) => a.id)).toEqual(firstIds);
    second.close();
  });

  it("backfills a legacy agent name that violates the v1.4 name rule verbatim", () => {
    const dbPath = join(tempDir, "legacy-name.vault.db");
    buildV11Db(dbPath, [["agent", "Old Agent"]]);

    const store = new SqliteStore(dbPath);
    expect(readAgents(store).map((a) => a.name)).toEqual(["Old Agent"]);
    store.close();
  });

  it("creates a fresh DB at v12 with both tables and all three indexes", () => {
    const dbPath = join(tempDir, "fresh.vault.db");
    const store = new SqliteStore(dbPath);
    expect(store.getMeta("schema_version")).toBe("12");

    const agentColumns = (
      store.db.prepare("PRAGMA table_info(agents)").all() as { name: string }[]
    ).map((c) => c.name);
    expect(agentColumns).toEqual([
      "id",
      "name",
      "description",
      "owner",
      "status",
      "created_at",
      "updated_at",
      "deactivated_at",
    ]);

    const tokenColumns = (
      store.db.prepare("PRAGMA table_info(issued_tokens)").all() as { name: string }[]
    ).map((c) => c.name);
    expect(tokenColumns).toEqual([
      "jti",
      "subject",
      "principal_type",
      "agent_id",
      "scope",
      "project",
      "secrets",
      "label",
      "issued_at",
      "expires_at",
      "revoked_at",
    ]);

    const indexNames = (
      store.db.prepare("SELECT name FROM sqlite_master WHERE type = 'index'").all() as {
        name: string;
      }[]
    ).map((i) => i.name);
    expect(indexNames).toContain("idx_issued_tokens_agent");
    expect(indexNames).toContain("idx_issued_tokens_expires");
    expect(indexNames).toContain("idx_audit_principal");

    const auditIndexColumns = (
      store.db.prepare("PRAGMA index_info(idx_audit_principal)").all() as { name: string }[]
    ).map((c) => c.name);
    expect(auditIndexColumns).toEqual(["principal_type", "principal_id", "timestamp"]);
    store.close();
  });

  it("declares ON DELETE SET NULL on issued_tokens.agent_id", () => {
    const dbPath = join(tempDir, "fk.vault.db");
    const store = new SqliteStore(dbPath);

    const fks = store.db.prepare("PRAGMA foreign_key_list(issued_tokens)").all() as {
      table: string;
      from: string;
      to: string;
      on_delete: string;
    }[];
    expect(fks).toHaveLength(1);
    expect(fks[0]?.table).toBe("agents");
    expect(fks[0]?.from).toBe("agent_id");
    expect(fks[0]?.to).toBe("id");
    expect(fks[0]?.on_delete).toBe("SET NULL");
    store.close();
  });

  it("nulls agent_id when the referenced agent row is deleted", () => {
    const dbPath = join(tempDir, "fk-cascade.vault.db");
    const store = new SqliteStore(dbPath);
    const now = Date.now();

    store.db
      .prepare(
        `INSERT INTO agents (id, name, description, owner, status, created_at, updated_at, deactivated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run("agent-id-1", "alpha", null, null, "active", now, now, null);
    store.db
      .prepare(
        `INSERT INTO issued_tokens (
          jti, subject, principal_type, agent_id, scope, project, secrets, label,
          issued_at, expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        "jti-1",
        "alpha",
        "agent",
        "agent-id-1",
        JSON.stringify(["read"]),
        null,
        null,
        null,
        now,
        now + 60_000,
        null,
      );

    store.db.prepare("DELETE FROM agents WHERE id = ?").run("agent-id-1");
    const row = store.db
      .prepare("SELECT agent_id, subject FROM issued_tokens WHERE jti = ?")
      .get("jti-1") as { agent_id: string | null; subject: string };
    expect(row.agent_id).toBeNull();
    expect(row.subject).toBe("alpha");
    store.close();
  });
});
