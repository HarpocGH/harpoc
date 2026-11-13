import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentStatus, CallerContext, IssuedTokenStatusFilter } from "@harpoc/shared";
import {
  AGENT_DESCRIPTION_MAX_LENGTH,
  AuditEventType,
  ErrorCode,
  SecretType,
  TOKEN_LABEL_MAX_LENGTH,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DecryptedAuditEvent } from "./audit/audit-query.js";
import type { IssuedTokenRow, SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { nonReadAuditCount } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine;

const CALLER: CallerContext = {
  principal_type: "user",
  principal_id: "admin-1",
  interface: "rest",
};

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

function vaultReads(...operations: string[]): DecryptedAuditEvent[] {
  return rows(AuditEventType.VAULT_READ).filter((row) =>
    operations.includes(row.detail?.operation as string),
  );
}

function failedDetails(eventType: AuditEventType): unknown[] {
  return engine.queryAudit({ eventType, success: false }).map((row) => row.detail);
}

/**
 * Seed a live token for a registered agent directly, bypassing `createToken`:
 * the cascade fixtures need tokens with a chosen jti, expiry or revocation
 * stamp, which the mint path does not offer.
 */
function seedToken(agentName: string, jti: string, overrides: Partial<IssuedTokenRow> = {}): void {
  const store = liveStore();
  const agent = store.getAgentByName(agentName);
  store.insertIssuedToken({
    jti,
    subject: agentName,
    principal_type: "agent",
    agent_id: agent ? agent.id : null,
    scope: ["read"],
    project: null,
    secrets: null,
    label: null,
    issued_at: Date.now(),
    expires_at: Date.now() + 3_600_000,
    revoked_at: null,
    ...overrides,
  });
}

async function makeSecret(name: string): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from("v", "utf8")),
  });
  return engine.resolveSecretId(`secret://${name}`);
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

describe("registerAgent", () => {
  it("returns the agent with its derived fields and writes an agent.register row", () => {
    const agent = engine.registerAgent({ name: "alpha", description: "bot", owner: "ops" });

    expect(agent).toMatchObject({
      name: "alpha",
      description: "bot",
      owner: "ops",
      status: "active",
      deactivated_at: null,
      last_active_at: null,
      active_tokens: 0,
      grants: 0,
    });

    const registered = rows(AuditEventType.AGENT_REGISTER);
    expect(registered).toHaveLength(1);
    expect(registered[0]?.detail).toMatchObject({ name: "alpha", owner: "ops" });
    expect(registered[0]?.success).toBe(true);
  });

  it("refuses a duplicate registration with AGENT_EXISTS and one failed agent.register row carrying the error alone", async () => {
    engine.registerAgent({ name: "alpha" });
    await expectVaultError(() => engine.registerAgent({ name: "alpha" }), ErrorCode.AGENT_EXISTS);
    const registered = rows(AuditEventType.AGENT_REGISTER);
    expect(registered.filter((row) => row.success)).toHaveLength(1);
    expect(failedDetails(AuditEventType.AGENT_REGISTER)).toEqual([
      { error: ErrorCode.AGENT_EXISTS },
    ]);
  });

  it("refuses an invalid name before writing anything", async () => {
    await expectVaultError(
      () => engine.registerAgent({ name: "bad name" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(engine.listAgents("all")).toHaveLength(0);
    expect(rows(AuditEventType.AGENT_REGISTER)).toHaveLength(0);
  });

  it("attributes the row to a caller and tags the interface", () => {
    engine.registerAgent({ name: "alpha" }, CALLER);

    const row = rows(AuditEventType.AGENT_REGISTER)[0];
    expect(row?.principal_type).toBe("user");
    expect(row?.principal_id).toBe("admin-1");
    expect(row?.detail).toMatchObject({ interface: "rest" });
  });

  it("leaves NULL principal columns on the trusted local path", () => {
    engine.registerAgent({ name: "alpha" });

    const row = rows(AuditEventType.AGENT_REGISTER)[0];
    expect(row?.principal_type).toBeNull();
    expect(row?.principal_id).toBeNull();
  });

  it("rolls the insert back when the audit write fails", () => {
    failNextAuditInsert();
    expect(() => engine.registerAgent({ name: "alpha" })).toThrow("audit unavailable");
    expect(liveStore().getAgentByName("alpha")).toBeUndefined();
  });
});

describe("getAgent / listAgents", () => {
  it("reads back an agent by name and writes one vault.read row and no other", () => {
    engine.registerAgent({ name: "alpha" });
    const before = nonReadAuditCount(engine);

    expect(engine.getAgent("alpha")).toMatchObject({ name: "alpha", status: "active" });
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(vaultReads("get_agent")).toHaveLength(1);
  });

  it("refuses an unknown agent with AGENT_NOT_FOUND naming the register command", async () => {
    const err = await expectVaultError(() => engine.getAgent("missing"), ErrorCode.AGENT_NOT_FOUND);
    expect(err.message).toContain("harpoc agent register");
  });

  it("lists active agents by default and inactive ones only under an explicit filter", () => {
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "beta" });
    engine.deactivateAgent("beta");

    expect(engine.listAgents().map((a) => a.name)).toEqual(["alpha"]);
    expect(engine.listAgents("inactive").map((a) => a.name)).toEqual(["beta"]);
    expect(engine.listAgents("all").map((a) => a.name)).toEqual(["alpha", "beta"]);
  });

  it("reports the derived counts of an agent that holds tokens and grants", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alpha", permissions: ["read"] },
      "test-admin",
    );
    seedToken("alpha", "jti-live");

    expect(engine.getAgent("alpha")).toMatchObject({ active_tokens: 1, grants: 1 });
  });

  it("an agent's listing does not move its last_active_at; a later non-read row of the same agent does (TW-R3)", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alpha", permissions: ["read", "list"] },
      "test-admin",
    );
    const alpha: CallerContext = { principal_type: "agent", principal_id: "alpha" };
    const start = Date.now();

    vi.useFakeTimers({ now: start + 60_000, toFake: ["Date"] });
    try {
      await engine.getSecretInfo("secret://db-password", alpha);
      vi.setSystemTime(start + 120_000);
      expect(engine.listSecrets(undefined, alpha)).toHaveLength(1);
      expect(engine.getAgent("alpha").last_active_at).toBe(start + 60_000);

      vi.setSystemTime(start + 180_000);
      await engine.getSecretInfo("secret://db-password", alpha);
      expect(engine.getAgent("alpha").last_active_at).toBe(start + 180_000);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("updateAgent", () => {
  it("replaces the metadata and audits the fields it carried", () => {
    engine.registerAgent({ name: "alpha", description: "old", owner: "ops" });

    const updated = engine.updateAgent("alpha", { description: "new" });

    expect(updated.description).toBe("new");
    expect(updated.owner).toBeNull();

    const audited = rows(AuditEventType.AGENT_UPDATE);
    expect(audited).toHaveLength(1);
    expect(audited[0]?.detail).toMatchObject({ name: "alpha", fields: ["description"] });
  });

  it("audits both fields when both are supplied", () => {
    engine.registerAgent({ name: "alpha" });
    engine.updateAgent("alpha", { description: "d", owner: "o" });
    expect(rows(AuditEventType.AGENT_UPDATE)[0]?.detail).toMatchObject({
      fields: ["description", "owner"],
    });
  });

  it("refuses an unknown agent", async () => {
    await expectVaultError(() => engine.updateAgent("missing", {}), ErrorCode.AGENT_NOT_FOUND);
  });

  it("rolls the update back when the audit write fails", () => {
    engine.registerAgent({ name: "alpha", description: "old" });
    failNextAuditInsert();
    expect(() => engine.updateAgent("alpha", { description: "new" })).toThrow("audit unavailable");
    expect(liveStore().getAgentByName("alpha")?.description).toBe("old");
  });
});

describe("deactivateAgent", () => {
  it("revokes every live token of the agent in one transaction", () => {
    engine.registerAgent({ name: "alpha" });
    seedToken("alpha", "jti-1");
    seedToken("alpha", "jti-2");

    expect(engine.deactivateAgent("alpha")).toEqual({ revoked_tokens: 2 });

    expect(engine.isTokenRevoked("jti-1")).toBe(true);
    expect(engine.isTokenRevoked("jti-2")).toBe(true);
    expect(engine.getAgent("alpha")).toMatchObject({ status: "inactive", active_tokens: 0 });
    expect(liveStore().getAgentByName("alpha")?.deactivated_at).not.toBeNull();

    const revocations = rows(AuditEventType.TOKEN_REVOKE);
    expect(revocations).toHaveLength(2);
    expect(revocations.map((r) => r.detail?.jti).sort()).toEqual(["jti-1", "jti-2"]);
    for (const row of revocations) {
      expect(row.detail).toMatchObject({ reason: "agent_deactivated" });
    }

    const deactivations = rows(AuditEventType.AGENT_DEACTIVATE);
    expect(deactivations).toHaveLength(1);
    expect(deactivations[0]?.detail).toMatchObject({ name: "alpha", revoked_tokens: 2 });
  });

  it("mirrors the revocation onto the issued-token row", () => {
    engine.registerAgent({ name: "alpha" });
    seedToken("alpha", "jti-1");

    engine.deactivateAgent("alpha");

    expect(liveStore().listIssuedTokens()[0]?.revoked_at).not.toBeNull();
  });

  it("leaves expired and already-revoked tokens alone", () => {
    engine.registerAgent({ name: "alpha" });
    seedToken("alpha", "jti-expired", { expires_at: Date.now() - 1 });
    seedToken("alpha", "jti-revoked", { revoked_at: Date.now() });

    expect(engine.deactivateAgent("alpha")).toEqual({ revoked_tokens: 0 });
    expect(engine.isTokenRevoked("jti-expired")).toBe(false);
    expect(engine.isTokenRevoked("jti-revoked")).toBe(false);
  });

  it("keeps the agent's policy grants", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alpha", permissions: ["read"] },
      "test-admin",
    );

    engine.deactivateAgent("alpha");

    expect(engine.listPolicies(secretId)).toHaveLength(1);
  });

  it("is idempotent on an inactive agent — 0 tokens, still audited", () => {
    engine.registerAgent({ name: "alpha" });
    engine.deactivateAgent("alpha");

    expect(engine.deactivateAgent("alpha")).toEqual({ revoked_tokens: 0 });
    expect(rows(AuditEventType.AGENT_DEACTIVATE)).toHaveLength(2);
  });

  it("does not re-stamp deactivated_at on a repeat deactivation", () => {
    engine.registerAgent({ name: "alpha" });
    engine.deactivateAgent("alpha");
    const first = liveStore().getAgentByName("alpha");

    vi.useFakeTimers({ now: Date.now() + 60_000, toFake: ["Date"] });
    try {
      engine.deactivateAgent("alpha");
    } finally {
      vi.useRealTimers();
    }

    const second = liveStore().getAgentByName("alpha");
    expect(second?.deactivated_at).toBe(first?.deactivated_at);
    expect(second?.updated_at).toBe(first?.updated_at);
  });

  it("refuses an unknown agent", async () => {
    await expectVaultError(() => engine.deactivateAgent("missing"), ErrorCode.AGENT_NOT_FOUND);
  });

  it("leaves the agent active and the tokens live when the audit write fails", () => {
    engine.registerAgent({ name: "alpha" });
    seedToken("alpha", "jti-1");

    failNextAuditInsert();
    expect(() => engine.deactivateAgent("alpha")).toThrow("audit unavailable");

    expect(liveStore().getAgentByName("alpha")?.status).toBe("active");
    expect(engine.isTokenRevoked("jti-1")).toBe(false);
    expect(liveStore().listIssuedTokens()[0]?.revoked_at).toBeNull();
  });

  it("a deactivated agent's token is refused by verifyToken, whose prune runs first (R9/C33-A: the entry carries the token's own registry expiry, in ms)", async () => {
    engine.registerAgent({ name: "alpha" });
    const token = engine.createToken("alpha", ["read"]);
    const { exp } = engine.verifyToken(token);

    engine.deactivateAgent("alpha");

    await expectVaultError(() => engine.verifyToken(token), ErrorCode.TOKEN_REVOKED);

    const denylist = liveStore().db.prepare("SELECT expires_at FROM revoked_tokens").all() as {
      expires_at: number;
    }[];
    expect(denylist).toHaveLength(1);
    expect(denylist[0]?.expires_at).toBe(exp * 1000);
  });

  it("attributes the cascade rows to the caller", () => {
    engine.registerAgent({ name: "alpha" });
    seedToken("alpha", "jti-1");

    engine.deactivateAgent("alpha", CALLER);

    const attributed = [
      ...rows(AuditEventType.TOKEN_REVOKE),
      ...rows(AuditEventType.AGENT_DEACTIVATE),
    ];
    expect(attributed).toHaveLength(2);
    for (const row of attributed) {
      expect(row.principal_type).toBe("user");
      expect(row.principal_id).toBe("admin-1");
      expect(row.detail).toMatchObject({ interface: "rest" });
    }
  });
});

describe("activateAgent", () => {
  it("restores the status but leaves revoked tokens revoked", () => {
    engine.registerAgent({ name: "alpha" });
    seedToken("alpha", "jti-1");
    engine.deactivateAgent("alpha");

    const agent = engine.activateAgent("alpha");

    expect(agent).toMatchObject({ status: "active", deactivated_at: null });
    expect(engine.isTokenRevoked("jti-1")).toBe(true);

    const activations = rows(AuditEventType.AGENT_ACTIVATE);
    expect(activations).toHaveLength(1);
    expect(activations[0]?.detail).toMatchObject({ name: "alpha" });
  });

  it("refuses an unknown agent", async () => {
    await expectVaultError(() => engine.activateAgent("missing"), ErrorCode.AGENT_NOT_FOUND);
  });

  it("rolls the status write back when the audit write fails", () => {
    engine.registerAgent({ name: "alpha" });
    engine.deactivateAgent("alpha");

    failNextAuditInsert();
    expect(() => engine.activateAgent("alpha")).toThrow("audit unavailable");
    expect(liveStore().getAgentByName("alpha")?.status).toBe("inactive");
  });
});

describe("deleteAgent", () => {
  it("revokes live tokens, removes grants and drops the agent in one transaction", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alpha", permissions: ["read"] },
      "test-admin",
    );
    seedToken("alpha", "jti-1");

    expect(engine.deleteAgent("alpha")).toEqual({ revoked_tokens: 1, removed_grants: 1 });

    expect(engine.isTokenRevoked("jti-1")).toBe(true);
    expect(engine.listPolicies(secretId)).toHaveLength(0);
    await expectVaultError(() => engine.getAgent("alpha"), ErrorCode.AGENT_NOT_FOUND);

    const revocations = rows(AuditEventType.POLICY_REVOKE);
    expect(revocations).toHaveLength(1);
    expect(revocations[0]?.secret_id).toBe(secretId);
    expect(revocations[0]?.detail).toMatchObject({ reason: "agent_deleted" });
    expect(revocations[0]?.detail?.policy_id).toBeTruthy();

    expect(rows(AuditEventType.TOKEN_REVOKE)[0]?.detail).toMatchObject({
      jti: "jti-1",
      reason: "agent_deleted",
    });

    const deletions = rows(AuditEventType.AGENT_DELETE);
    expect(deletions).toHaveLength(1);
    expect(deletions[0]?.detail).toMatchObject({
      name: "alpha",
      revoked_tokens: 1,
      removed_grants: 1,
    });
  });

  it("keeps the issued-token history with a NULL agent_id", () => {
    engine.registerAgent({ name: "alpha" });
    seedToken("alpha", "jti-1");

    engine.deleteAgent("alpha");

    const stored = liveStore().listIssuedTokens();
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ jti: "jti-1", subject: "alpha", agent_id: null });
  });

  it("leaves another principal's grants untouched", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.registerAgent({ name: "beta" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alpha", permissions: ["read"] },
      "test-admin",
    );
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "beta", permissions: ["read"] },
      "test-admin",
    );
    engine.grantPolicy(
      { secretId, principalType: "tool", principalId: "alpha", permissions: ["read"] },
      "test-admin",
    );

    expect(engine.deleteAgent("alpha")).toEqual({ revoked_tokens: 0, removed_grants: 1 });
    expect(engine.listPolicies(secretId)).toHaveLength(2);
  });

  it("refuses an unknown agent", async () => {
    await expectVaultError(() => engine.deleteAgent("missing"), ErrorCode.AGENT_NOT_FOUND);
  });

  it("rolls the whole cascade back when the audit write fails", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "alpha" });
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alpha", permissions: ["read"] },
      "test-admin",
    );
    seedToken("alpha", "jti-1");

    failNextAuditInsert();
    expect(() => engine.deleteAgent("alpha")).toThrow("audit unavailable");

    expect(liveStore().getAgentByName("alpha")).toBeDefined();
    expect(engine.isTokenRevoked("jti-1")).toBe(false);
    expect(engine.listPolicies(secretId)).toHaveLength(1);
  });
});

describe("sealed vault", () => {
  it("refuses every agent method with VAULT_LOCKED", async () => {
    engine.registerAgent({ name: "alpha" });
    await engine.lock();

    await expectVaultError(() => engine.registerAgent({ name: "beta" }), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.getAgent("alpha"), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.listAgents(), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.updateAgent("alpha", {}), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.activateAgent("alpha"), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.deactivateAgent("alpha"), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.deleteAgent("alpha"), ErrorCode.VAULT_LOCKED);
  });
});

describe("createToken registration gate", () => {
  it("refuses an unregistered agent-typed subject with one failed token.create row and no token", async () => {
    const err = await expectVaultError(
      () => engine.createToken("ghost", ["use"]),
      ErrorCode.AGENT_NOT_FOUND,
    );
    expect(err.message).toContain("harpoc agent register ghost");

    const created = rows(AuditEventType.TOKEN_CREATE);
    expect(created.map((row) => [row.success, row.principal_id, row.detail])).toEqual([
      [false, null, { error: ErrorCode.AGENT_NOT_FOUND }],
    ]);
    expect(JSON.stringify(created[0]?.detail).includes("ghost")).toBe(false);
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
  });

  it("refuses a deactivated agent with AGENT_INACTIVE and one failed token.create row", async () => {
    engine.registerAgent({ name: "ghost" });
    engine.deactivateAgent("ghost");

    await expectVaultError(() => engine.createToken("ghost", ["use"]), ErrorCode.AGENT_INACTIVE);
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
    expect(failedDetails(AuditEventType.TOKEN_CREATE)).toEqual([
      { error: ErrorCode.AGENT_INACTIVE },
    ]);
  });

  it("issues for a registered agent and records the claims metadata", () => {
    const agent = engine.registerAgent({ name: "ghost" });
    const token = engine.createToken("ghost", ["use"]);
    expect(typeof token).toBe("string");

    const listed = engine.listIssuedTokens();
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({
      subject: "ghost",
      agent: "ghost",
      principal_type: "agent",
      scope: ["use"],
      project: null,
      secrets: null,
      label: null,
      revoked_at: null,
      status: "active",
    });
    expect(listed[0]?.jti).toBeTruthy();
    expect(listed[0]?.expires_at).toBeGreaterThan(Date.now());

    const stored = liveStore().listIssuedTokens();
    expect(stored[0]?.agent_id).toBe(agent.id);
  });

  it("carries the label into the registry row and the token.create detail", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"], 60_000, { label: "ci" });

    expect(engine.listIssuedTokens()[0]?.label).toBe("ci");
    expect(rows(AuditEventType.TOKEN_CREATE)[0]?.detail).toMatchObject({
      subject: "ghost",
      label: "ci",
      principal_type: "agent",
    });
  });

  it("omits the label from the audit detail when none was supplied", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"]);

    expect(rows(AuditEventType.TOKEN_CREATE)[0]?.detail).not.toHaveProperty("label");
  });

  it("refuses a label over the maximum length before any vault state is read: no row (U-7), no token", async () => {
    engine.registerAgent({ name: "ghost" });
    const label = `refused-label-${"x".repeat(256)}`;
    const before = nonReadAuditCount(engine);

    await expectVaultError(
      () => engine.createToken("ghost", ["use"], 60_000, { label }),
      ErrorCode.INVALID_INPUT,
    );
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(rows(AuditEventType.TOKEN_CREATE)).toEqual([]);
  });

  it("accepts a label exactly at the maximum length", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"], 60_000, { label: "x".repeat(TOKEN_LABEL_MAX_LENGTH) });

    expect(engine.listIssuedTokens()[0]?.label).toHaveLength(TOKEN_LABEL_MAX_LENGTH);
  });

  it("needs no registration for a tool-typed principal and lists with a null agent", () => {
    engine.createToken("svc", ["use"], 60_000, { principalType: "tool" });

    const listed = engine.listIssuedTokens();
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({ subject: "svc", agent: null, principal_type: "tool" });
    expect(liveStore().listIssuedTokens()[0]?.agent_id).toBeNull();
  });

  it("records the project and secret patterns it was scoped to", () => {
    engine.createToken("ops", ["read"], 60_000, {
      principalType: "user",
      project: "acme",
      secrets: ["db-*"],
    });

    expect(engine.listIssuedTokens()[0]).toMatchObject({
      project: "acme",
      secrets: ["db-*"],
      principal_type: "user",
    });
  });

  it("leaves no issued-token row when the audit write fails", () => {
    engine.registerAgent({ name: "ghost" });

    failNextAuditInsert();
    expect(() => engine.createToken("ghost", ["use"])).toThrow("audit unavailable");

    expect(liveStore().listIssuedTokens()).toHaveLength(0);
  });
});

describe("grantPolicy registration gate", () => {
  it("refuses an unregistered agent principal before writing a policy row, with one failed policy.grant row", async () => {
    const secretId = await makeSecret("db-password");

    await expectVaultError(
      () =>
        engine.grantPolicy(
          { secretId, principalType: "agent", principalId: "ghost2", permissions: ["read"] },
          "test-admin",
          CALLER,
        ),
      ErrorCode.AGENT_NOT_FOUND,
    );
    expect(engine.listPolicies(secretId)).toHaveLength(0);
    const granted = rows(AuditEventType.POLICY_GRANT);
    expect(
      granted.map((row) => [row.success, row.secret_id, row.principal_id, row.detail]),
    ).toEqual([[false, null, "admin-1", { error: ErrorCode.AGENT_NOT_FOUND, interface: "rest" }]]);
    expect(JSON.stringify(granted[0]?.detail).includes("ghost2")).toBe(false);
  });

  it("refuses a deactivated agent principal with AGENT_INACTIVE and one failed policy.grant row", async () => {
    const secretId = await makeSecret("db-password");
    engine.registerAgent({ name: "ghost2" });
    engine.deactivateAgent("ghost2");

    await expectVaultError(
      () =>
        engine.grantPolicy(
          { secretId, principalType: "agent", principalId: "ghost2", permissions: ["read"] },
          "test-admin",
        ),
      ErrorCode.AGENT_INACTIVE,
    );
    expect(failedDetails(AuditEventType.POLICY_GRANT)).toEqual([
      { error: ErrorCode.AGENT_INACTIVE },
    ]);
  });

  it("refuses a create grant before reaching the registration gate", async () => {
    const secretId = await makeSecret("db-password");

    await expectVaultError(
      () =>
        engine.grantPolicy(
          { secretId, principalType: "agent", principalId: "ghost2", permissions: ["create"] },
          "test-admin",
        ),
      ErrorCode.INVALID_INPUT,
    );
  });

  it("leaves tool principals ungated", async () => {
    const secretId = await makeSecret("db-password");

    const policy = engine.grantPolicy(
      { secretId, principalType: "tool", principalId: "ghost2", permissions: ["read"] },
      "test-admin",
    );
    expect(policy.principal_id).toBe("ghost2");
  });
});

describe("listIssuedTokens", () => {
  it("derives revoked status from the mirror and stamps revoked_at once", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"]);
    const jti = engine.listIssuedTokens()[0]?.jti as string;

    engine.revokeToken(jti);

    const revoked = engine.listIssuedTokens({ status: "revoked" });
    expect(revoked).toHaveLength(1);
    expect(revoked[0]?.status).toBe("revoked");
    const firstStamp = revoked[0]?.revoked_at;
    expect(firstStamp).not.toBeNull();

    engine.revokeToken(jti);
    expect(engine.listIssuedTokens({ status: "revoked" })[0]?.revoked_at).toBe(firstStamp);
  });

  it("defaults to active only", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"]);
    const live = engine.listIssuedTokens()[0]?.jti as string;
    engine.createToken("ghost", ["use"]);
    const doomed = engine.listIssuedTokens().find((t) => t.jti !== live)?.jti as string;
    engine.revokeToken(doomed);

    const listed = engine.listIssuedTokens();
    expect(listed).toHaveLength(1);
    expect(listed[0]?.jti).toBe(live);
  });

  it("reports an elapsed token as expired and includes it under 'all'", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"], 0);

    expect(engine.listIssuedTokens()).toHaveLength(0);
    const all = engine.listIssuedTokens({ status: "all" });
    expect(all).toHaveLength(1);
    expect(all[0]?.status).toBe("expired");
    expect(engine.listIssuedTokens({ status: "expired" })).toHaveLength(1);
  });

  it("filters by agent name", () => {
    engine.registerAgent({ name: "ghost" });
    engine.registerAgent({ name: "other" });
    engine.createToken("ghost", ["use"]);
    engine.createToken("other", ["use"]);
    engine.createToken("svc", ["use"], 60_000, { principalType: "tool" });

    const listed = engine.listIssuedTokens({ agent: "ghost" });
    expect(listed).toHaveLength(1);
    expect(listed[0]?.subject).toBe("ghost");
  });

  it("refuses an unknown agent filter", async () => {
    await expectVaultError(
      () => engine.listIssuedTokens({ agent: "missing" }),
      ErrorCode.AGENT_NOT_FOUND,
    );
  });

  it("orders newest first and writes one vault.read row and no other", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["read"]);
    engine.createToken("ghost", ["use"]);
    const before = nonReadAuditCount(engine);

    const listed = engine.listIssuedTokens();
    expect(listed).toHaveLength(2);
    expect(listed[0]?.issued_at).toBeGreaterThanOrEqual(listed[1]?.issued_at as number);
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(vaultReads("list_tokens")).toHaveLength(1);
  });

  it("keeps the row of a deleted agent with a null agent name", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"]);

    engine.deleteAgent("ghost");

    const all = engine.listIssuedTokens({ status: "all" });
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ subject: "ghost", agent: null, status: "revoked" });
  });

  it("mirrors the JWT claims: an empty scope narrowing lists as unrestricted", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"], 60_000, { secrets: [], project: "" });

    const listed = engine.listIssuedTokens()[0];
    expect(listed?.secrets).toBeNull();
    expect(listed?.project).toBeNull();
  });

  it("refuses on a sealed vault", async () => {
    await engine.lock();
    await expectVaultError(() => engine.listIssuedTokens(), ErrorCode.VAULT_LOCKED);
  });
});

describe("revokeToken attribution", () => {
  it("attributes the token.revoke row to a caller and tags the interface", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"]);
    const jti = engine.listIssuedTokens()[0]?.jti as string;

    engine.revokeToken(jti, CALLER);

    const row = rows(AuditEventType.TOKEN_REVOKE)[0];
    expect(row?.principal_type).toBe("user");
    expect(row?.principal_id).toBe("admin-1");
    expect(row?.detail).toMatchObject({ jti, interface: "rest" });
  });

  it("leaves NULL principal columns on the trusted local path", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["use"]);
    const jti = engine.listIssuedTokens()[0]?.jti as string;

    engine.revokeToken(jti);

    const row = rows(AuditEventType.TOKEN_REVOKE)[0];
    expect(row?.principal_type).toBeNull();
    expect(row?.principal_id).toBeNull();
    expect(row?.detail).toEqual({ jti });
  });
});

describe("the registry reads' vault.read rows (A5)", () => {
  const NAMES = ["ledger-bot", "payroll-bot"];

  function storedJtis(): string[] {
    return liveStore()
      .listIssuedTokens()
      .map((row) => row.jti);
  }

  it("getAgent: one row after the read — found true, the caller's principal — naming no agent", () => {
    engine.registerAgent({ name: "ledger-bot" });
    const before = nonReadAuditCount(engine);

    expect(engine.getAgent("ledger-bot", CALLER)).toMatchObject({ name: "ledger-bot" });

    expect(nonReadAuditCount(engine)).toBe(before);
    const reads = vaultReads("get_agent");
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatchObject({
      event_type: AuditEventType.VAULT_READ,
      secret_id: null,
      principal_type: "user",
      principal_id: "admin-1",
      success: true,
    });
    expect(reads[0]?.detail).toEqual({ operation: "get_agent", found: true, interface: "rest" });
    expect(JSON.stringify(reads[0]?.detail).includes("ledger-bot")).toBe(false);
  });

  it("listAgents: one row a call — the status verbatim, the count, the caller's principal — naming no agent", () => {
    engine.registerAgent({ name: "ledger-bot" });
    engine.registerAgent({ name: "payroll-bot" });
    engine.deactivateAgent("payroll-bot");
    const before = nonReadAuditCount(engine);

    expect(engine.listAgents(undefined, CALLER).map((a) => a.name)).toEqual(["ledger-bot"]);
    expect(engine.listAgents("inactive", CALLER).map((a) => a.name)).toEqual(["payroll-bot"]);
    expect(engine.listAgents("all", CALLER)).toHaveLength(2);

    expect(nonReadAuditCount(engine)).toBe(before);
    const reads = vaultReads("list_agents");
    expect(reads.map((row) => [row.principal_type, row.principal_id, row.detail])).toEqual([
      ["user", "admin-1", { operation: "list_agents", status: "all", count: 2, interface: "rest" }],
      [
        "user",
        "admin-1",
        { operation: "list_agents", status: "inactive", count: 1, interface: "rest" },
      ],
      [
        "user",
        "admin-1",
        { operation: "list_agents", status: "active", count: 1, interface: "rest" },
      ],
    ]);
    const serialized = JSON.stringify(reads.map((row) => row.detail));
    for (const name of NAMES) expect(serialized.includes(name)).toBe(false);
  });

  it("listIssuedTokens: one row a call — the status verbatim, the agent filter by its presence, the count — naming no agent, label or jti", () => {
    engine.registerAgent({ name: "ledger-bot" });
    engine.registerAgent({ name: "payroll-bot" });
    engine.createToken("ledger-bot", ["use"], 60_000, { label: "nightly-sync" });
    engine.createToken("payroll-bot", ["use"]);
    const jtis = storedJtis();
    expect(jtis).toHaveLength(2);
    const before = nonReadAuditCount(engine);

    expect(engine.listIssuedTokens({ agent: "ledger-bot", status: "all" }, CALLER)).toHaveLength(1);
    expect(engine.listIssuedTokens(undefined, CALLER)).toHaveLength(2);

    expect(nonReadAuditCount(engine)).toBe(before);
    const reads = vaultReads("list_tokens");
    expect(reads.map((row) => [row.principal_type, row.principal_id, row.detail])).toEqual([
      [
        "user",
        "admin-1",
        { operation: "list_tokens", status: "active", count: 2, interface: "rest" },
      ],
      [
        "user",
        "admin-1",
        { operation: "list_tokens", status: "all", agent: true, count: 1, interface: "rest" },
      ],
    ]);
    const serialized = JSON.stringify(reads.map((row) => row.detail));
    for (const text of [...NAMES, "nightly-sync", ...jtis]) {
      expect(serialized.includes(text)).toBe(false);
    }
  });

  it("a status outside its vocabulary is recorded by its presence, the text in no part of the detail", () => {
    engine.registerAgent({ name: "ledger-bot" });

    expect(engine.listAgents("ledger-owner" as AgentStatus, CALLER)).toEqual([]);
    expect(
      engine.listIssuedTokens({ status: "payroll-run" as IssuedTokenStatusFilter }, CALLER),
    ).toEqual([]);

    const reads = vaultReads("list_agents", "list_tokens");
    expect(reads.map((row) => row.detail)).toEqual([
      { operation: "list_tokens", status: true, count: 0, interface: "rest" },
      { operation: "list_agents", status: true, count: 0, interface: "rest" },
    ]);
    const serialized = JSON.stringify(reads.map((row) => row.detail));
    for (const text of ["ledger-owner", "payroll-run"]) {
      expect(serialized.includes(text)).toBe(false);
    }
  });

  it("the trusted path writes the three rows with NULL principal columns and no interface key", () => {
    engine.registerAgent({ name: "ledger-bot" });

    engine.getAgent("ledger-bot");
    engine.listAgents();
    engine.listIssuedTokens();

    expect(
      vaultReads("get_agent", "list_agents", "list_tokens").map((row) => [
        row.principal_type,
        row.principal_id,
        row.detail,
      ]),
    ).toEqual([
      [null, null, { operation: "list_tokens", status: "active", count: 0 }],
      [null, null, { operation: "list_agents", status: "active", count: 1 }],
      [null, null, { operation: "get_agent", found: true }],
    ]);
  });

  it("an unknown agent stays AGENT_NOT_FOUND on getAgent and the token filter, each with one failed vault.read row of its operation naming no agent", async () => {
    await expectVaultError(() => engine.getAgent("missing", CALLER), ErrorCode.AGENT_NOT_FOUND);
    await expectVaultError(
      () => engine.listIssuedTokens({ agent: "missing" }, CALLER),
      ErrorCode.AGENT_NOT_FOUND,
    );

    const reads = vaultReads("get_agent", "list_tokens");
    expect(reads.map((row) => [row.success, row.principal_id, row.detail])).toEqual([
      [false, "admin-1", { operation: "list_tokens", error: "AGENT_NOT_FOUND", interface: "rest" }],
      [false, "admin-1", { operation: "get_agent", error: "AGENT_NOT_FOUND", interface: "rest" }],
    ]);
    expect(JSON.stringify(reads.map((row) => row.detail)).includes("missing")).toBe(false);
  });

  it.each([
    ["getAgent", "get_agent", () => engine.getAgent("ledger-bot", CALLER)],
    ["listAgents", "list_agents", () => engine.listAgents("all", CALLER)],
    ["listIssuedTokens", "list_tokens", () => engine.listIssuedTokens({ status: "all" }, CALLER)],
  ])(
    "%s throws the logger's error and returns nothing when its row cannot be written",
    (_label, operation, read) => {
      engine.registerAgent({ name: "ledger-bot" });
      failNextAuditInsert();

      let answer: unknown;
      expect(() => {
        answer = read();
      }).toThrow("audit unavailable");
      expect(answer).toBeUndefined();
      expect(vaultReads(operation)).toEqual([]);
    },
  );

  it("an admin scoped to a project finds none of these rows on the trail; an unscoped read finds them (A-2)", () => {
    engine.registerAgent({ name: "ledger-bot" });
    engine.getAgent("ledger-bot", CALLER);
    engine.listAgents("all", CALLER);
    engine.listIssuedTokens(undefined, CALLER);

    const scoped = engine.queryAudit({}, { project: "web" });
    expect(scoped.length).toBeGreaterThan(0);
    expect(scoped.filter((row) => row.event_type === AuditEventType.VAULT_READ)).toEqual([]);
    expect(
      vaultReads("get_agent", "list_agents", "list_tokens").map((row) => row.detail?.operation),
    ).toEqual(["list_tokens", "list_agents", "get_agent"]);
  });
});

describe("the registry's refusals write one failed row of the operation's own type (A7)", () => {
  const UNKNOWN = "unknown-ledger-bot";

  it.each([
    ["updateAgent", AuditEventType.AGENT_UPDATE, () => engine.updateAgent(UNKNOWN, {}, CALLER)],
    ["activateAgent", AuditEventType.AGENT_ACTIVATE, () => engine.activateAgent(UNKNOWN, CALLER)],
    [
      "deactivateAgent",
      AuditEventType.AGENT_DEACTIVATE,
      () => engine.deactivateAgent(UNKNOWN, CALLER),
    ],
    ["deleteAgent", AuditEventType.AGENT_DELETE, () => engine.deleteAgent(UNKNOWN, CALLER)],
  ])(
    "%s of an unknown agent: AGENT_NOT_FOUND, one failed row with the caller's principal and the error alone",
    async (_label, eventType, refused) => {
      await expectVaultError(refused, ErrorCode.AGENT_NOT_FOUND);

      const written = rows(eventType);
      expect(
        written.map((row) => [row.success, row.secret_id, row.principal_id, row.detail]),
      ).toEqual([
        [false, null, "admin-1", { error: ErrorCode.AGENT_NOT_FOUND, interface: "rest" }],
      ]);
      expect(JSON.stringify(written[0]).includes(UNKNOWN)).toBe(false);
    },
  );

  it("registerAgent of a taken name: the failed agent.register row carries the caller's principal, not the name", async () => {
    engine.registerAgent({ name: "ledger-bot" });

    await expectVaultError(
      () => engine.registerAgent({ name: "ledger-bot", owner: "ops" }, CALLER),
      ErrorCode.AGENT_EXISTS,
    );

    const failed = engine.queryAudit({ eventType: AuditEventType.AGENT_REGISTER, success: false });
    expect(failed.map((row) => [row.principal_id, row.detail])).toEqual([
      ["admin-1", { error: ErrorCode.AGENT_EXISTS, interface: "rest" }],
    ]);
    expect(JSON.stringify(failed[0]?.detail).includes("ledger-bot")).toBe(false);
  });

  it.each([
    ["an unknown agent", ErrorCode.AGENT_NOT_FOUND, false],
    ["a deactivated agent", ErrorCode.AGENT_INACTIVE, true],
  ])(
    "setAgentPermissions for %s: one failed policy.grant row with the error alone, no secret id, no cell written",
    async (_label, code, registered) => {
      const secretId = await makeSecret("db-password");
      if (registered) {
        engine.registerAgent({ name: UNKNOWN });
        engine.deactivateAgent(UNKNOWN);
      }

      await expectVaultError(
        () => engine.setAgentPermissions(UNKNOWN, secretId, ["read"], undefined, "op", CALLER),
        code,
      );

      expect(engine.listPolicies(secretId)).toHaveLength(0);
      const granted = rows(AuditEventType.POLICY_GRANT);
      expect(
        granted.map((row) => [row.success, row.secret_id, row.principal_id, row.detail]),
      ).toEqual([[false, null, "admin-1", { error: code, interface: "rest" }]]);
      expect(JSON.stringify(granted[0]).includes(UNKNOWN)).toBe(false);
    },
  );

  it("createToken with a principal type outside agent, tool and user is refused before any vault state is read: no row (U-7), no token", async () => {
    const before = nonReadAuditCount(engine);

    await expectVaultError(
      () =>
        engine.createToken("svc", ["use"], 60_000, {
          principalType: "refused-principal" as never,
        }),
      ErrorCode.INVALID_INPUT,
    );

    expect(nonReadAuditCount(engine)).toBe(before);
    expect(rows(AuditEventType.TOKEN_CREATE)).toEqual([]);
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
  });

  it("a schema refusal before any read stays row-less (U-7): an invalid name on registerAgent and updateAgent", async () => {
    engine.registerAgent({ name: "ledger-bot" });
    const before = nonReadAuditCount(engine);

    await expectVaultError(
      () => engine.registerAgent({ name: "bad name" }),
      ErrorCode.INVALID_INPUT,
    );
    await expectVaultError(
      () =>
        engine.updateAgent("ledger-bot", {
          description: "d".repeat(AGENT_DESCRIPTION_MAX_LENGTH + 1),
        }),
      ErrorCode.INVALID_INPUT,
    );

    expect(nonReadAuditCount(engine)).toBe(before);
  });
});
