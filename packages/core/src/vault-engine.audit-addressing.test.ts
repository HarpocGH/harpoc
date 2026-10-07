import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

/**
 * What an audit row carries and who may read it: secret_id on the lifecycle
 * rows (L4), the create row's attribution (L3), the token-scoped visibility
 * filter (L10) and the chain across them.
 */

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

const VALUE = Buffer.from("super-secret-value", "utf8");

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function agent(id: string, project?: string): CallerContext {
  const caller: CallerContext = { principal_type: "agent", principal_id: id, interface: "rest" };
  if (project) caller.project = project;
  return caller;
}

async function makeSecret(name: string, project?: string, expiresAt?: number): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    project,
    value: new Uint8Array(VALUE),
    expiresAt,
  });
  return engine.resolveSecretId(project ? `secret://${project}/${name}` : `secret://${name}`);
}

// ---------------------------------------------------------------------------
// L4 — the six credential-lifecycle success rows carry secret_id
// ---------------------------------------------------------------------------

describe("L4 — lifecycle success rows are addressable by secret_id", () => {
  it("stamps secret_id on create, read, get_value, set, rotate and revoke", async () => {
    await engine.createSecret({ name: "pending-key", type: SecretType.API_KEY });
    const pendingId = await engine.resolveSecretId("secret://pending-key");
    await engine.setSecretValue("secret://pending-key", new Uint8Array(VALUE));

    const id = await makeSecret("lifecycle");
    await engine.getSecretInfo("secret://lifecycle");
    await engine.getSecretValue("secret://lifecycle");
    await engine.rotateSecret("secret://lifecycle", new Uint8Array(Buffer.from("rotated")));
    await engine.revokeSecret("secret://lifecycle");

    // The whole point of the finding: `audit --secret <id>` used to omit
    // exactly the successful reads/rotations/revocations of that secret.
    const scoped = engine.queryAudit({ secretId: id });
    const types = scoped.filter((r) => r.success).map((r) => r.event_type);
    expect(types).toContain(AuditEventType.SECRET_CREATE);
    expect(types).toContain(AuditEventType.SECRET_READ);
    expect(types).toContain(AuditEventType.SECRET_ROTATE);
    expect(types).toContain(AuditEventType.SECRET_REVOKE);
    // Two reads: getSecretInfo and getSecretValue.
    expect(scoped.filter((r) => r.event_type === AuditEventType.SECRET_READ)).toHaveLength(2);

    const setRow = engine
      .queryAudit({ secretId: pendingId })
      .find((r) => r.detail?.action === "set_value");
    expect(setRow).toBeDefined();
  });

  it("stamps secret_id on a denial row once the handle resolved", async () => {
    const id = await makeSecret("denied-read");
    await engine.revokeSecret("secret://denied-read");

    await expect(engine.getSecretValue("secret://denied-read")).rejects.toMatchObject({
      code: ErrorCode.SECRET_REVOKED,
    });

    const denial = engine
      .queryAudit({ secretId: id })
      .find((r) => !r.success && r.event_type === AuditEventType.SECRET_READ);
    expect(denial).toBeDefined();
    expect(denial?.detail?.error).toBe(ErrorCode.SECRET_REVOKED);
  });

  it("negative control: an unresolvable handle still audits without a secret_id", async () => {
    await expect(engine.getSecretInfo("secret://ghost")).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });
    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success);
    expect(row?.secret_id).toBeNull();
  });

  // The three denial arms that pass no resolved id at all: nothing resolved, so
  // NULL is the honest column value — and a later refactor that reaches for a
  // "nearby" id instead would mis-attribute a row about a secret that was never
  // found.

  it("a failed revoke of an unresolvable handle audits with secret_id null", async () => {
    await expect(engine.revokeSecret("secret://ghost")).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });

    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_REVOKE })
      .find((r) => !r.success);
    expect(row).toBeDefined();
    expect(row?.secret_id).toBeNull();
  });

  it("a failed useSecret handle resolution audits with secret_id null", async () => {
    await expect(
      engine.useSecret("secret://ghost", {
        type: "http",
        method: "GET",
        url: "https://example.invalid/",
        injection: { type: "bearer" },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.SECRET_NOT_FOUND });

    const row = engine.queryAudit({ eventType: AuditEventType.SECRET_USE }).find((r) => !r.success);
    expect(row).toBeDefined();
    expect(row?.secret_id).toBeNull();
  });

  it("a caller-present unresolvable handle audits the policy denial with secret_id null", async () => {
    // With a caller the refusal happens one layer earlier, in
    // enforceCallerPolicy's own resolution attempt — a different auditDenied
    // call site from the negative control above.
    await expect(engine.getSecretInfo("secret://ghost", agent("mallory"))).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });

    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success);
    expect(row).toBeDefined();
    expect(row?.principal_id).toBe("mallory");
    expect(row?.secret_id).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// L3 — createSecret is attributed to its caller
// ---------------------------------------------------------------------------

describe("L3 — create attribution", () => {
  it("attributes the create row to the requesting principal and interface", async () => {
    await engine.createSecret(
      { name: "made-by-agent", type: SecretType.API_KEY, value: new Uint8Array(VALUE) },
      agent("agent-7"),
    );

    const row = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE })[0];
    expect(row?.principal_type).toBe("agent");
    expect(row?.principal_id).toBe("agent-7");
    expect(row?.detail?.interface).toBe("rest");
  });

  it("control: a caller-less create stays NULL-principal (trusted local path)", async () => {
    await engine.createSecret({
      name: "made-locally",
      type: SecretType.API_KEY,
      value: new Uint8Array(VALUE),
    });

    const row = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE })[0];
    expect(row?.principal_id).toBeNull();
    expect(row?.detail?.interface).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// L10 — audit reads honour the token's project / name-pattern scope
// ---------------------------------------------------------------------------

describe("L10 — audit visibility scope", () => {
  beforeEach(async () => {
    // Rows carrying a secret_id, produced by a path that stamped it long before
    // L4 — so this suite pins the visibility filter alone.
    for (const [name, project] of [
      ["db-prod", undefined],
      ["api-key", undefined],
      ["billing", "finance"],
    ] as [string, string | undefined][]) {
      const id = await makeSecret(name, project);
      registerAgents(engine, `reader-${name}`);
      engine.grantPolicy(
        {
          secretId: id,
          principalType: "agent",
          principalId: `reader-${name}`,
          permissions: ["read"],
        },
        "test-admin",
      );
    }
  });

  it("drops rows about secrets outside the token's name patterns", async () => {
    const dbId = await engine.resolveSecretId("secret://db-prod");
    const apiId = await engine.resolveSecretId("secret://api-key");

    const visible = engine.queryAudit({}, { secrets: ["db-*"] });
    const ids = visible.map((r) => r.secret_id).filter((id): id is string => id !== null);

    expect(ids).toContain(dbId);
    expect(ids).not.toContain(apiId);
  });

  it("answers a targeted secret_id query about a foreign secret with nothing", async () => {
    const apiId = await engine.resolveSecretId("secret://api-key");
    expect(engine.queryAudit({ secretId: apiId }, { secrets: ["db-*"] })).toEqual([]);
    // Control: the same query without the scope does return the rows.
    expect(engine.queryAudit({ secretId: apiId }).length).toBeGreaterThan(0);
  });

  it("drops rows about other projects' secrets", async () => {
    const billingId = await engine.resolveSecretId("secret://finance/billing");
    const dbId = await engine.resolveSecretId("secret://db-prod");

    const visible = engine.queryAudit({}, { project: "finance" });
    const ids = visible.map((r) => r.secret_id).filter((id): id is string => id !== null);

    expect(ids).toContain(billingId);
    expect(ids).not.toContain(dbId);
  });

  it("keeps vault-level rows, which carry no per-secret metadata (D2)", () => {
    const visible = engine.queryAudit({}, { secrets: ["db-*"] });
    expect(visible.some((r) => r.event_type === AuditEventType.VAULT_UNLOCK)).toBe(true);
  });

  it("applies the visibility filter before the limit (a scoped limit=2 still returns the older in-scope row)", async () => {
    const dbId = await engine.resolveSecretId("secret://db-prod");
    const apiId = await engine.resolveSecretId("secret://api-key");
    await engine.getSecretInfo("secret://db-prod");
    for (let i = 0; i < 3; i++) await engine.getSecretInfo("secret://api-key");

    const visible = engine.queryAudit(
      { eventType: AuditEventType.SECRET_READ, limit: 2 },
      { secrets: ["db-*"] },
    );

    expect(visible.map((r) => r.secret_id)).toContain(dbId);
    expect(visible.map((r) => r.secret_id)).not.toContain(apiId);
  });

  it("control: an unscoped read (CLI / unrestricted admin token) sees everything", async () => {
    const apiId = await engine.resolveSecretId("secret://api-key");
    const all = engine.queryAudit();
    expect(all.map((r) => r.secret_id)).toContain(apiId);
    expect(engine.queryAudit({}, undefined).length).toBe(all.length);
  });
});

describe("L5/L10 sanity", () => {
  it("the audit chain stays valid across the attributed and scoped rows", async () => {
    await makeSecret("chain-check");
    await engine.getSecretInfo("secret://chain-check");
    await engine.revokeSecret("secret://chain-check");
    const report = engine.verifyAuditChain();
    expect(report.valid).toBe(true);
  });
});
