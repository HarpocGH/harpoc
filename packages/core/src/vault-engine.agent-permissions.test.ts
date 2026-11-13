import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DecryptedAuditEvent } from "./audit/audit-query.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { nonReadAuditCount } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine;

function agent(name: string): CallerContext {
  return { principal_type: "agent", principal_id: name, interface: "rest" };
}

function liveStore(): SqliteStore {
  return (engine as unknown as { store: SqliteStore }).store;
}

function failNextAuditInsert(): void {
  vi.spyOn(liveStore(), "insertAuditEvent").mockImplementationOnce(() => {
    throw new Error("audit unavailable");
  });
}

function rows(eventType: AuditEventType): DecryptedAuditEvent[] {
  return engine.queryAudit({ eventType });
}

function vaultReads(operation: string): DecryptedAuditEvent[] {
  return rows(AuditEventType.VAULT_READ).filter((row) => row.detail?.operation === operation);
}

async function makeSecret(name: string, project?: string): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    project,
    value: new Uint8Array(Buffer.from("v", "utf8")),
  });
  return engine.resolveSecretId(`secret://${project ? `${project}/` : ""}${name}`);
}

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-agov-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("setAgentPermissions", () => {
  it("grants the cell and reports the gating flip", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });

    const result = engine.setAgentPermissions(
      "alpha",
      secretId,
      ["read", "use"],
      undefined,
      "test-admin",
    );

    expect(result.gated_before).toBe(false);
    expect(result.gated_after).toBe(true);
    expect(result.policy).toMatchObject({
      secret_id: secretId,
      principal_type: "agent",
      principal_id: "alpha",
      permissions: ["read", "use"],
      expires_at: null,
      created_by: "test-admin",
    });

    const granted = rows(AuditEventType.POLICY_GRANT);
    expect(granted).toHaveLength(1);
    expect(granted[0]?.secret_id).toBe(secretId);
    expect(granted[0]?.success).toBe(true);
    expect(granted[0]?.detail).toMatchObject({
      policy_id: result.policy?.id,
      principal: "agent:alpha",
    });
  });

  it("carries an expiry onto the stored row", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    const expiresAt = Date.now() + 60_000;

    const result = engine.setAgentPermissions("alpha", secretId, ["read"], expiresAt, "test-admin");

    expect(result.policy?.expires_at).toBe(expiresAt);
  });

  it("replaces the agent's rows on a re-cell, auditing the removal as replaced", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });

    const first = engine.setAgentPermissions(
      "alpha",
      secretId,
      ["read", "use"],
      undefined,
      "test-admin",
    );
    const second = engine.setAgentPermissions("alpha", secretId, ["use"], undefined, "test-admin");

    const stored = engine
      .listPolicies(secretId)
      .filter((p) => p.principal_type === "agent" && p.principal_id === "alpha");
    expect(stored).toHaveLength(1);
    expect(stored[0]?.permissions).toEqual(["use"]);
    expect(stored[0]?.id).toBe(second.policy?.id);

    expect(second.gated_before).toBe(true);
    expect(second.gated_after).toBe(true);

    const revoked = rows(AuditEventType.POLICY_REVOKE);
    expect(revoked).toHaveLength(1);
    expect(revoked[0]?.secret_id).toBe(secretId);
    expect(revoked[0]?.detail).toMatchObject({ policy_id: first.policy?.id, replaced: true });
    expect(rows(AuditEventType.POLICY_GRANT)).toHaveLength(2);
  });

  it("clears the agent's only grant and reports the secret ungated", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    const first = engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin");

    const cleared = engine.setAgentPermissions("alpha", secretId, [], undefined, "test-admin");

    expect(cleared).toMatchObject({ policy: null, gated_before: true, gated_after: false });
    expect(engine.listPolicies(secretId)).toHaveLength(0);

    const revoked = rows(AuditEventType.POLICY_REVOKE);
    expect(revoked).toHaveLength(1);
    expect(revoked[0]?.detail).toMatchObject({ policy_id: first.policy?.id, replaced: true });
    expect(rows(AuditEventType.POLICY_GRANT)).toHaveLength(1);
  });

  it("writes nothing at all for an empty cell on an agent with no rows", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    const before = nonReadAuditCount(engine);

    const result = engine.setAgentPermissions("alpha", secretId, [], undefined, "test-admin");

    expect(result).toMatchObject({ policy: null, gated_before: false, gated_after: false });
    expect(nonReadAuditCount(engine)).toBe(before);
  });

  it("leaves another agent's grant on the same secret intact", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "beta" });
    engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin");
    const betaGrant = engine.setAgentPermissions(
      "beta",
      secretId,
      ["use"],
      undefined,
      "test-admin",
    );

    const cleared = engine.setAgentPermissions("alpha", secretId, [], undefined, "test-admin");

    expect(cleared).toMatchObject({ policy: null, gated_before: true, gated_after: true });
    const stored = engine.listPolicies(secretId);
    expect(stored).toHaveLength(1);
    expect(stored[0]?.id).toBe(betaGrant.policy?.id);
  });

  it("refuses a create permission with the same message grantPolicy uses", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });

    const matrixThrown = await expectVaultError(
      () => engine.setAgentPermissions("alpha", secretId, ["create"], undefined, "test-admin"),
      ErrorCode.INVALID_INPUT,
    );
    const grantThrown = await expectVaultError(
      () =>
        engine.grantPolicy(
          {
            secretId,
            principalType: "agent",
            principalId: "alpha",
            permissions: ["create"],
          },
          "test-admin",
        ),
      ErrorCode.INVALID_INPUT,
    );

    expect(matrixThrown.message).toBe(grantThrown.message);
    expect(engine.listPolicies(secretId)).toHaveLength(0);
    expect(rows(AuditEventType.POLICY_GRANT)).toHaveLength(0);
  });

  it("refuses create before the registration gate", async () => {
    const secretId = await makeSecret("db-password");

    await expectVaultError(
      () => engine.setAgentPermissions("ghost", secretId, ["create"], undefined, "test-admin"),
      ErrorCode.INVALID_INPUT,
    );
  });

  it("refuses an unregistered agent", async () => {
    const secretId = await makeSecret("db-password");

    await expectVaultError(
      () => engine.setAgentPermissions("ghost", secretId, ["read"], undefined, "test-admin"),
      ErrorCode.AGENT_NOT_FOUND,
    );
    expect(engine.listPolicies(secretId)).toHaveLength(0);
  });

  it("refuses a deactivated agent", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.deactivateAgent("alpha");

    await expectVaultError(
      () => engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin"),
      ErrorCode.AGENT_INACTIVE,
    );
    expect(engine.listPolicies(secretId)).toHaveLength(0);
  });

  it("refuses a token caller without admin on a gated secret and audits it as via matrix", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "bob" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alpha", permissions: ["use"] },
      "test-admin",
    );

    await expectVaultError(
      () =>
        engine.setAgentPermissions(
          "alpha",
          secretId,
          ["read"],
          undefined,
          "test-admin",
          agent("bob"),
        ),
      ErrorCode.ACCESS_DENIED,
    );

    const denial = rows(AuditEventType.POLICY_GRANT).find((r) => !r.success);
    expect(denial?.secret_id).toBe(secretId);
    expect(denial?.principal_type).toBe("agent");
    expect(denial?.principal_id).toBe("bob");
    expect(denial?.detail).toMatchObject({
      policy: "access",
      principal: "agent:alpha",
      via: "matrix",
      required_permission: "admin",
      error: ErrorCode.ACCESS_DENIED,
      interface: "rest",
    });
    expect(engine.listPolicies(secretId)).toHaveLength(1);
  });

  it("lets a token caller holding admin write the cell", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "root" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "root", permissions: ["admin"] },
      "test-admin",
    );

    const result = engine.setAgentPermissions(
      "alpha",
      secretId,
      ["read"],
      undefined,
      "test-admin",
      agent("root"),
    );

    expect(result.policy?.principal_id).toBe("alpha");
    const granted = rows(AuditEventType.POLICY_GRANT).filter(
      (r) => r.success && r.detail?.principal === "agent:alpha",
    );
    expect(granted[0]?.principal_id).toBe("root");
    expect(granted[0]?.detail).toMatchObject({ interface: "rest" });
  });

  it("never checks the trusted local path on a gated secret", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "beta" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "beta", permissions: ["use"] },
      "test-admin",
    );

    const result = engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin");

    expect(result.policy?.principal_id).toBe("alpha");
    const granted = rows(AuditEventType.POLICY_GRANT).find(
      (r) => r.detail?.principal === "agent:alpha",
    );
    expect(granted?.principal_id).toBeNull();
    expect(granted?.detail?.interface).toBeUndefined();
  });

  it("rolls the whole cell back when an audit write fails mid-transaction", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    const first = engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin");
    const auditBefore = nonReadAuditCount(engine);

    failNextAuditInsert();
    expect(() =>
      engine.setAgentPermissions("alpha", secretId, ["use"], undefined, "test-admin"),
    ).toThrow("audit unavailable");

    const stored = engine.listPolicies(secretId);
    expect(stored).toHaveLength(1);
    expect(stored[0]?.id).toBe(first.policy?.id);
    expect(stored[0]?.permissions).toEqual(["read"]);
    expect(
      engine
        .queryAudit()
        .filter(
          (r) =>
            r.event_type !== AuditEventType.VAULT_READ && r.detail?.config !== "access_policies",
        ),
    ).toHaveLength(auditBefore);
  });

  it("refuses on a sealed vault", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    await engine.lock();

    await expectVaultError(
      () => engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin"),
      ErrorCode.VAULT_LOCKED,
    );
  });
});

describe("listAgentPolicies", () => {
  it("resolves the handle of every non-expired grant and writes one vault.read row and no other", async () => {
    const plain = await makeSecret("db-password");
    const scoped = await makeSecret("api-key", "billing");
    engine.registerAgent({ name: "alpha" });
    const a = engine.setAgentPermissions("alpha", plain, ["read"], undefined, "test-admin");
    const b = engine.setAgentPermissions("alpha", scoped, ["use"], undefined, "test-admin");
    const before = nonReadAuditCount(engine);

    const listed = engine.listAgentPolicies("alpha");

    expect(listed).toHaveLength(2);
    expect(listed.find((p) => p.secret_id === plain)).toMatchObject({
      policy_id: a.policy?.id,
      handle: "secret://db-password",
      permissions: ["read"],
      expires_at: null,
    });
    expect(listed.find((p) => p.secret_id === scoped)).toMatchObject({
      policy_id: b.policy?.id,
      handle: "secret://billing/api-key",
      permissions: ["use"],
    });
    expect(listed[0]?.created_at).toBeGreaterThan(0);
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(vaultReads("list_agent_policies")).toHaveLength(1);
  });

  it("excludes expired rows", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.setAgentPermissions("alpha", secretId, ["read"], Date.now() - 1_000, "test-admin");

    expect(engine.listAgentPolicies("alpha")).toHaveLength(0);
  });

  it("lists only the named agent's grants", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "beta" });
    engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin");
    engine.setAgentPermissions("beta", secretId, ["use"], undefined, "test-admin");

    const listed = engine.listAgentPolicies("beta");
    expect(listed).toHaveLength(1);
    expect(listed[0]?.permissions).toEqual(["use"]);
  });

  it("keeps a deactivated agent's grants visible", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.setAgentPermissions("alpha", secretId, ["read"], undefined, "test-admin");
    engine.deactivateAgent("alpha");

    expect(engine.listAgentPolicies("alpha")).toHaveLength(1);
  });

  it("refuses an unknown agent", async () => {
    await expectVaultError(() => engine.listAgentPolicies("ghost"), ErrorCode.AGENT_NOT_FOUND);
  });

  it("skips a row whose secret no longer exists", async () => {
    const kept = await makeSecret("db-password");
    const doomed = await makeSecret("gone");
    engine.registerAgent({ name: "alpha" });
    engine.setAgentPermissions("alpha", kept, ["read"], undefined, "test-admin");
    engine.setAgentPermissions("alpha", doomed, ["use"], undefined, "test-admin");

    // The FK would cascade the policy row away with its secret; dropping the
    // secret with FK enforcement off is the only way to observe the engine's
    // own defence against an unresolvable secret id.
    const store = liveStore();
    store.db.pragma("foreign_keys = OFF");
    store.db.prepare("DELETE FROM secrets WHERE id = ?").run(doomed);
    store.db.pragma("foreign_keys = ON");

    const listed = engine.listAgentPolicies("alpha");
    expect(listed).toHaveLength(1);
    expect(listed[0]?.secret_id).toBe(kept);
  });

  it("refuses on a sealed vault", async () => {
    engine.registerAgent({ name: "alpha" });
    await engine.lock();

    await expectVaultError(() => engine.listAgentPolicies("alpha"), ErrorCode.VAULT_LOCKED);
  });
});

describe("the grant listings' vault.read rows (A5)", () => {
  const OPERATOR: CallerContext = {
    principal_type: "user",
    principal_id: "operator",
    interface: "rest",
  };
  const ADMIN_USER: CallerContext = { ...OPERATOR, admin_scope: true };

  async function grantedVault(): Promise<string[]> {
    const ledger = await makeSecret("ledger", "finance");
    const payroll = await makeSecret("payroll");
    engine.registerAgent({ name: "ledger-bot" });
    engine.setAgentPermissions("ledger-bot", ledger, ["read"], undefined, "test-admin");
    engine.setAgentPermissions("ledger-bot", payroll, ["use"], undefined, "test-admin");
    return [ledger, payroll];
  }

  const NAMES = ["ledger-bot", "ledger", "payroll", "finance", "secret://"];

  it("listAgentPolicies: one row after the read — the count, the caller's principal — naming no agent, secret or handle", async () => {
    const ids = await grantedVault();
    const before = nonReadAuditCount(engine);

    expect(engine.listAgentPolicies("ledger-bot", OPERATOR)).toHaveLength(2);

    expect(nonReadAuditCount(engine)).toBe(before);
    const reads = vaultReads("list_agent_policies");
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({
      event_type: AuditEventType.VAULT_READ,
      secret_id: null,
      principal_type: "user",
      principal_id: "operator",
      success: true,
    });
    expect(reads[0]?.detail).toEqual({
      operation: "list_agent_policies",
      count: 2,
      interface: "rest",
    });
    const serialized = JSON.stringify(reads[0]?.detail);
    for (const text of [...NAMES, ...ids]) expect(serialized.includes(text)).toBe(false);
  });

  it("listAgentPolicies on the trusted path writes its row with NULL principal columns and no interface key", async () => {
    await grantedVault();

    engine.listAgentPolicies("ledger-bot");

    expect(
      vaultReads("list_agent_policies").map((row) => [
        row.principal_type,
        row.principal_id,
        row.detail,
      ]),
    ).toEqual([[null, null, { operation: "list_agent_policies", count: 2 }]]);
  });

  it("listAgentPolicies of an unknown agent stays AGENT_NOT_FOUND with one failed vault.read row of its operation, naming no agent", async () => {
    await expectVaultError(
      () => engine.listAgentPolicies("missing", OPERATOR),
      ErrorCode.AGENT_NOT_FOUND,
    );

    const reads = vaultReads("list_agent_policies");
    expect(reads.map((row) => [row.success, row.principal_id, row.detail])).toEqual([
      [
        false,
        "operator",
        { operation: "list_agent_policies", error: "AGENT_NOT_FOUND", interface: "rest" },
      ],
    ]);
    expect(JSON.stringify(reads[0]?.detail).includes("missing")).toBe(false);
  });

  it("listPolicies without a secret: one vault.read row with the count — the trusted path with NULL principal columns, an admin-scoped user token with its own — naming no secret or principal", async () => {
    const ids = await grantedVault();
    const before = nonReadAuditCount(engine);

    expect(engine.listPolicies()).toHaveLength(2);
    expect(engine.listPolicies(undefined, ADMIN_USER)).toHaveLength(2);

    expect(nonReadAuditCount(engine)).toBe(before);
    const reads = vaultReads("list_policies");
    expect(reads.map((row) => [row.secret_id, row.principal_id, row.detail])).toEqual([
      [null, "operator", { operation: "list_policies", count: 2, interface: "rest" }],
      [null, null, { operation: "list_policies", count: 2 }],
    ]);
    const serialized = JSON.stringify(reads.map((row) => row.detail));
    for (const text of [...NAMES, ...ids]) expect(serialized.includes(text)).toBe(false);
  });

  it("listPolicies with a secret id keeps its secret.read row and writes no vault.read row", async () => {
    const [ledger] = await grantedVault();

    expect(engine.listPolicies(ledger, ADMIN_USER)).toHaveLength(1);

    expect(vaultReads("list_policies")).toEqual([]);
    expect(
      rows(AuditEventType.SECRET_READ)
        .filter((row) => row.detail?.config === "access_policies")
        .map((row) => [row.secret_id, row.principal_id, row.detail]),
    ).toEqual([[ledger, "operator", { config: "access_policies", interface: "rest" }]]);
  });

  it("listPolicies refuses a scoped caller without a secret id INVALID_INPUT before any read, with no row (U-7)", async () => {
    await grantedVault();
    const before = nonReadAuditCount(engine);

    await expectVaultError(
      () => engine.listPolicies(undefined, agent("ledger-bot")),
      ErrorCode.INVALID_INPUT,
    );

    expect(nonReadAuditCount(engine)).toBe(before);
    expect(vaultReads("list_policies")).toEqual([]);
  });

  it.each([
    ["listAgentPolicies", "list_agent_policies", () => engine.listAgentPolicies("ledger-bot")],
    ["listPolicies", "list_policies", () => engine.listPolicies()],
  ])(
    "%s throws the logger's error and returns nothing when its row cannot be written",
    async (_label, operation, read) => {
      await grantedVault();
      failNextAuditInsert();

      let answer: unknown;
      expect(() => {
        answer = read();
      }).toThrow("audit unavailable");
      expect(answer).toBeUndefined();
      expect(vaultReads(operation)).toEqual([]);
    },
  );
});

describe("queryAudit principal filter", () => {
  it("returns only the named principal's attributed rows", async () => {
    const first = await makeSecret("first");
    const second = await makeSecret("second");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "gamma" });
    engine.registerAgent({ name: "target" });

    engine.grantPolicy(
      { secretId: first, principalType: "agent", principalId: "alpha", permissions: ["admin"] },
      "operator",
    );
    engine.grantPolicy(
      { secretId: second, principalType: "agent", principalId: "gamma", permissions: ["admin"] },
      "operator",
    );

    engine.setAgentPermissions("target", first, ["read"], undefined, "admin", agent("alpha"));
    engine.setAgentPermissions("target", second, ["read"], undefined, "admin", agent("gamma"));

    const mine = engine.queryAudit({ principalType: "agent", principalId: "alpha" });
    expect(mine).toHaveLength(1);
    expect(mine[0]?.secret_id).toBe(first);
    expect(mine.every((r) => r.principal_id === "alpha")).toBe(true);

    expect(engine.queryAudit({ principalType: "agent", principalId: "gamma" })).toHaveLength(1);
    expect(engine.queryAudit({ principalId: "alpha" })).toHaveLength(1);
    expect(engine.queryAudit({ principalType: "user", principalId: "alpha" })).toHaveLength(0);
  });

  it("composes with the visibility scope", async () => {
    const mine = await makeSecret("api-key", "billing");
    const theirs = await makeSecret("api-key", "ops");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "target" });

    engine.grantPolicy(
      { secretId: mine, principalType: "agent", principalId: "alpha", permissions: ["admin"] },
      "operator",
    );
    engine.grantPolicy(
      { secretId: theirs, principalType: "agent", principalId: "alpha", permissions: ["admin"] },
      "operator",
    );

    engine.setAgentPermissions("target", mine, ["read"], undefined, "admin", agent("alpha"));
    engine.setAgentPermissions("target", theirs, ["read"], undefined, "admin", agent("alpha"));

    expect(engine.queryAudit({ principalType: "agent", principalId: "alpha" })).toHaveLength(2);

    const scoped = engine.queryAudit(
      { principalType: "agent", principalId: "alpha" },
      { project: "billing" },
    );
    expect(scoped).toHaveLength(1);
    expect(scoped[0]?.secret_id).toBe(mine);
  });
});
