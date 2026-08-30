import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, TOKEN_LABEL_MAX_LENGTH } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DecryptedAuditEvent } from "./audit/audit-query.js";
import type { IssuedTokenRow, SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

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
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
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

  it("refuses a duplicate registration with AGENT_EXISTS", async () => {
    engine.registerAgent({ name: "alpha" });
    await expectVaultError(() => engine.registerAgent({ name: "alpha" }), ErrorCode.AGENT_EXISTS);
    expect(rows(AuditEventType.AGENT_REGISTER)).toHaveLength(1);
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
    expect(() => engine.registerAgent({ name: "alpha" })).toThrow();
    expect(liveStore().getAgentByName("alpha")).toBeUndefined();
  });
});

describe("getAgent / listAgents", () => {
  it("reads back an agent by name without writing an audit row", () => {
    engine.registerAgent({ name: "alpha" });
    const before = engine.queryAudit().length;

    expect(engine.getAgent("alpha")).toMatchObject({ name: "alpha", status: "active" });
    expect(engine.queryAudit()).toHaveLength(before);
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
    expect(() => engine.updateAgent("alpha", { description: "new" })).toThrow();
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
    expect(() => engine.deactivateAgent("alpha")).toThrow();

    expect(liveStore().getAgentByName("alpha")?.status).toBe("active");
    expect(engine.isTokenRevoked("jti-1")).toBe(false);
    expect(liveStore().listIssuedTokens()[0]?.revoked_at).toBeNull();
  });

  it("a deactivated agent's token is refused by verifyToken, whose prune runs first (R2: the denylist floor is in ms)", () => {
    engine.registerAgent({ name: "alpha" });
    const token = engine.createToken("alpha", ["read"]);

    engine.deactivateAgent("alpha");

    expect(() => engine.verifyToken(token)).toThrow("revoked");

    const denylist = liveStore().db.prepare("SELECT expires_at FROM revoked_tokens").all() as {
      expires_at: number;
    }[];
    expect(denylist).toHaveLength(1);
    expect(denylist[0]?.expires_at).toBeGreaterThanOrEqual(Date.now() + 23 * 60 * 60 * 1000);
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
    expect(() => engine.activateAgent("alpha")).toThrow();
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
    expect(() => engine.deleteAgent("alpha")).toThrow();

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
  it("refuses an unregistered agent-typed subject and writes nothing", async () => {
    const err = await expectVaultError(
      () => engine.createToken("ghost", ["use"]),
      ErrorCode.AGENT_NOT_FOUND,
    );
    expect(err.message).toContain("harpoc agent register ghost");

    expect(rows(AuditEventType.TOKEN_CREATE)).toHaveLength(0);
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
  });

  it("refuses a deactivated agent with AGENT_INACTIVE", async () => {
    engine.registerAgent({ name: "ghost" });
    engine.deactivateAgent("ghost");

    await expectVaultError(() => engine.createToken("ghost", ["use"]), ErrorCode.AGENT_INACTIVE);
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
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

  it("refuses a label over the maximum length before writing anything", async () => {
    engine.registerAgent({ name: "ghost" });

    await expectVaultError(
      () => engine.createToken("ghost", ["use"], 60_000, { label: "x".repeat(256) }),
      ErrorCode.INVALID_INPUT,
    );
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
    expect(rows(AuditEventType.TOKEN_CREATE)).toHaveLength(0);
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
    expect(() => engine.createToken("ghost", ["use"])).toThrow();

    expect(liveStore().listIssuedTokens()).toHaveLength(0);
  });
});

describe("grantPolicy registration gate", () => {
  it("refuses an unregistered agent principal before writing a policy row", async () => {
    const secretId = await makeSecret("db-password");

    await expectVaultError(
      () =>
        engine.grantPolicy(
          { secretId, principalType: "agent", principalId: "ghost2", permissions: ["read"] },
          "test-admin",
        ),
      ErrorCode.AGENT_NOT_FOUND,
    );
    expect(engine.listPolicies(secretId)).toHaveLength(0);
    expect(rows(AuditEventType.POLICY_GRANT)).toHaveLength(0);
  });

  it("refuses a deactivated agent principal with AGENT_INACTIVE", async () => {
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

  it("orders newest first and writes no audit row", () => {
    engine.registerAgent({ name: "ghost" });
    engine.createToken("ghost", ["read"]);
    engine.createToken("ghost", ["use"]);
    const before = engine.queryAudit().length;

    const listed = engine.listIssuedTokens();
    expect(listed).toHaveLength(2);
    expect(listed[0]?.issued_at).toBeGreaterThanOrEqual(listed[1]?.issued_at as number);
    expect(engine.queryAudit()).toHaveLength(before);
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

    engine.revokeToken(jti, undefined, CALLER);

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
