import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AccessPolicy, AuditEvent, Secret } from "@harpoc/shared";
import { AuditEventType, SecretStatus, SecretType } from "@harpoc/shared";
import type { AgentRow, IssuedTokenRow } from "./sqlite-store.js";
import { isUniqueConstraintError, SqliteStore } from "./sqlite-store.js";

let store: SqliteStore;
const NOW = 1_800_000_000_000;
const LINK = new Uint8Array(32).fill(7);

function makeSecret(id: string): Secret {
  return {
    id,
    name_encrypted: new Uint8Array([1]),
    name_iv: new Uint8Array(12),
    name_tag: new Uint8Array(16),
    type: SecretType.API_KEY,
    project: null,
    wrapped_dek: new Uint8Array([2]),
    dek_iv: new Uint8Array(12),
    dek_tag: new Uint8Array(16),
    ciphertext: new Uint8Array([3]),
    ct_iv: new Uint8Array(12),
    ct_tag: new Uint8Array(16),
    metadata_encrypted: null,
    metadata_iv: null,
    metadata_tag: null,
    created_at: NOW,
    updated_at: NOW,
    expires_at: null,
    rotated_at: null,
    version: 1,
    status: SecretStatus.ACTIVE,
    name_hmac: `hmac-${id}`,
  };
}

function makeAgent(overrides: Partial<AgentRow> = {}): AgentRow {
  return {
    id: "agent-id-1",
    name: "alpha",
    description: null,
    owner: null,
    status: "active",
    created_at: NOW,
    updated_at: NOW,
    deactivated_at: null,
    ...overrides,
  };
}

function makeToken(overrides: Partial<IssuedTokenRow> = {}): IssuedTokenRow {
  return {
    jti: "jti-1",
    subject: "alpha",
    principal_type: "agent",
    agent_id: "agent-id-1",
    scope: ["read", "use"],
    project: null,
    secrets: null,
    label: null,
    issued_at: NOW,
    expires_at: NOW + 60_000,
    revoked_at: null,
    ...overrides,
  };
}

function makePolicy(overrides: Partial<AccessPolicy> = {}): AccessPolicy {
  return {
    id: "policy-1",
    secret_id: "s1",
    principal_type: "agent",
    principal_id: "alpha",
    permissions: ["read"],
    created_at: NOW,
    expires_at: null,
    created_by: "user",
    ...overrides,
  };
}

function makeAuditEvent(overrides: Partial<Omit<AuditEvent, "id">> = {}): Omit<AuditEvent, "id"> {
  return {
    timestamp: NOW,
    event_type: AuditEventType.SECRET_READ,
    secret_id: null,
    principal_type: "agent",
    principal_id: "alpha",
    detail_encrypted: null,
    detail_iv: null,
    detail_tag: null,
    ip_address: null,
    session_id: null,
    success: true,
    ...overrides,
  };
}

beforeEach(() => {
  store = new SqliteStore(":memory:");
  store.insertSecret(makeSecret("s1"));
  store.insertSecret(makeSecret("s2"));
});

afterEach(() => {
  store.close();
});

describe("agents", () => {
  it("round-trips an inserted agent by id and by name", () => {
    const agent = makeAgent({ description: "build bot", owner: "ops@example.com" });
    store.insertAgent(agent);

    expect(store.getAgentById("agent-id-1")).toEqual(agent);
    expect(store.getAgentByName("alpha")).toEqual(agent);
  });

  it("returns undefined for an unknown agent", () => {
    expect(store.getAgentById("missing")).toBeUndefined();
    expect(store.getAgentByName("missing")).toBeUndefined();
  });

  it("rejects a duplicate name with a unique-constraint error", () => {
    store.insertAgent(makeAgent());
    let caught: unknown;
    try {
      store.insertAgent(makeAgent({ id: "agent-id-2" }));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(Error);
    expect(isUniqueConstraintError(caught)).toBe(true);
  });

  it("lists agents by status, ordered by name ascending", () => {
    store.insertAgent(makeAgent({ id: "a1", name: "zeta" }));
    store.insertAgent(makeAgent({ id: "a2", name: "alpha" }));
    store.insertAgent(makeAgent({ id: "a3", name: "beta", status: "inactive" }));

    expect(store.listAgents("all").map((a) => a.name)).toEqual(["alpha", "beta", "zeta"]);
    expect(store.listAgents("active").map((a) => a.name)).toEqual(["alpha", "zeta"]);
    expect(store.listAgents("inactive").map((a) => a.name)).toEqual(["beta"]);
  });

  it("replaces description and owner on updateAgentMetadata, leaving name and status", () => {
    store.insertAgent(makeAgent({ description: "old", owner: "old@example.com" }));
    store.updateAgentMetadata("agent-id-1", "new", null, NOW + 5_000);

    const updated = store.getAgentById("agent-id-1");
    expect(updated?.description).toBe("new");
    expect(updated?.owner).toBeNull();
    expect(updated?.updated_at).toBe(NOW + 5_000);
    expect(updated?.name).toBe("alpha");
    expect(updated?.status).toBe("active");
  });

  it("sets deactivated_at when deactivating and clears it when reactivating", () => {
    store.insertAgent(makeAgent());

    store.setAgentStatus("agent-id-1", "inactive", NOW + 1_000);
    const inactive = store.getAgentById("agent-id-1");
    expect(inactive?.status).toBe("inactive");
    expect(inactive?.updated_at).toBe(NOW + 1_000);
    expect(inactive?.deactivated_at).toBe(NOW + 1_000);

    store.setAgentStatus("agent-id-1", "active", NOW + 2_000);
    const active = store.getAgentById("agent-id-1");
    expect(active?.status).toBe("active");
    expect(active?.updated_at).toBe(NOW + 2_000);
    expect(active?.deactivated_at).toBeNull();
  });

  it("deletes an agent and reports whether a row was removed", () => {
    store.insertAgent(makeAgent());

    expect(store.deleteAgent("agent-id-1")).toBe(true);
    expect(store.getAgentById("agent-id-1")).toBeUndefined();
    expect(store.deleteAgent("agent-id-1")).toBe(false);
  });

  it("reads the most recent attributed audit timestamp as last-active", () => {
    store.insertAgent(makeAgent());
    expect(store.agentLastActiveAt("alpha")).toBeNull();

    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW - 10_000 }), LINK);
    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW - 500 }), LINK);
    store.insertAuditEvent(
      makeAuditEvent({ timestamp: NOW + 90_000, principal_type: "tool", principal_id: "alpha" }),
      LINK,
    );
    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW + 80_000, principal_id: "beta" }), LINK);

    expect(store.agentLastActiveAt("alpha")).toBe(NOW - 500);
    expect(store.agentLastActiveAt("beta")).toBe(NOW + 80_000);
  });
});

describe("issued_tokens", () => {
  beforeEach(() => {
    store.insertAgent(makeAgent());
  });

  it("round-trips a token and resolves the agent name through the LEFT JOIN", () => {
    const token = makeToken({ project: "proj", secrets: ["db-*"], label: "ci runner" });
    store.insertIssuedToken(token);

    const rows = store.listIssuedTokens();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({ ...token, agent_name: "alpha" });
  });

  it("stores a null agent_id and reports a null agent name", () => {
    store.insertIssuedToken(
      makeToken({ jti: "jti-user", subject: "ops", principal_type: "user", agent_id: null }),
    );

    const rows = store.listIssuedTokens();
    expect(rows[0]?.agent_id).toBeNull();
    expect(rows[0]?.agent_name).toBeNull();
    expect(rows[0]?.secrets).toBeNull();
  });

  it("orders listed tokens by issued_at descending and filters by agent", () => {
    store.insertAgent(makeAgent({ id: "agent-id-2", name: "beta" }));
    store.insertIssuedToken(makeToken({ jti: "old", issued_at: NOW - 10_000 }));
    store.insertIssuedToken(makeToken({ jti: "new", issued_at: NOW + 10_000 }));
    store.insertIssuedToken(
      makeToken({ jti: "other", subject: "beta", agent_id: "agent-id-2", issued_at: NOW }),
    );

    expect(store.listIssuedTokens().map((r) => r.jti)).toEqual(["new", "other", "old"]);
    expect(store.listIssuedTokens({ agentId: "agent-id-1" }).map((r) => r.jti)).toEqual([
      "new",
      "old",
    ]);
    expect(store.listIssuedTokens({ agentId: "agent-id-2" }).map((r) => r.jti)).toEqual(["other"]);
  });

  it("marks a token revoked only once", () => {
    store.insertIssuedToken(makeToken());

    store.markIssuedTokenRevoked("jti-1", NOW + 1_000);
    expect(store.listIssuedTokens()[0]?.revoked_at).toBe(NOW + 1_000);

    store.markIssuedTokenRevoked("jti-1", NOW + 9_000);
    expect(store.listIssuedTokens()[0]?.revoked_at).toBe(NOW + 1_000);
  });

  it("counts and lists only live tokens for an agent", () => {
    store.insertIssuedToken(makeToken({ jti: "live", expires_at: NOW + 60_000 }));
    store.insertIssuedToken(makeToken({ jti: "expired", expires_at: NOW - 1 }));
    store.insertIssuedToken(
      makeToken({ jti: "revoked", expires_at: NOW + 60_000, revoked_at: NOW - 100 }),
    );
    store.insertIssuedToken(makeToken({ jti: "boundary", expires_at: NOW }));

    expect(store.listLiveTokensForAgent("agent-id-1", NOW)).toEqual([
      { jti: "live", expires_at: NOW + 60_000 },
    ]);
    expect(store.countActiveTokensForAgent("agent-id-1", NOW)).toBe(1);
    expect(store.countActiveTokensForAgent("agent-id-1", NOW + 120_000)).toBe(0);
    expect(store.countActiveTokensForAgent("agent-id-2", NOW)).toBe(0);
  });

  it("getIssuedToken returns one row by jti and null for an unknown one", () => {
    store.insertIssuedToken(makeToken());

    expect(store.getIssuedToken("jti-1")).toEqual(makeToken());
    expect(store.getIssuedToken("nope")).toBeNull();
  });
});

describe("policy deletion by principal", () => {
  it("removes and returns exactly the matching principal's rows on one secret", () => {
    store.insertPolicy(makePolicy({ id: "p1", secret_id: "s1", principal_id: "alpha" }));
    store.insertPolicy(
      makePolicy({ id: "p2", secret_id: "s1", principal_id: "alpha", permissions: ["use"] }),
    );
    store.insertPolicy(makePolicy({ id: "p3", secret_id: "s1", principal_id: "beta" }));
    store.insertPolicy(
      makePolicy({ id: "p4", secret_id: "s1", principal_type: "tool", principal_id: "alpha" }),
    );
    store.insertPolicy(makePolicy({ id: "p5", secret_id: "s2", principal_id: "alpha" }));

    const removed = store.deletePoliciesForPrincipalOnSecret("s1", "agent", "alpha");
    expect(removed.map((p) => p.id).sort()).toEqual(["p1", "p2"]);
    expect(removed[0]?.permissions).toEqual(["read"]);

    const surviving = store
      .listPolicies()
      .map((p) => p.id)
      .sort();
    expect(surviving).toEqual(["p3", "p4", "p5"]);
    expect(store.deletePoliciesForPrincipalOnSecret("s1", "agent", "alpha")).toEqual([]);
  });

  it("removes and returns every row of a principal across secrets", () => {
    store.insertPolicy(makePolicy({ id: "p1", secret_id: "s1", principal_id: "alpha" }));
    store.insertPolicy(makePolicy({ id: "p2", secret_id: "s2", principal_id: "alpha" }));
    store.insertPolicy(makePolicy({ id: "p3", secret_id: "s1", principal_id: "beta" }));

    const removed = store.deletePoliciesForPrincipal("agent", "alpha");
    expect(removed.map((p) => p.id).sort()).toEqual(["p1", "p2"]);
    expect(store.listPolicies().map((p) => p.id)).toEqual(["p3"]);
  });

  it("counts a principal's non-expired policies", () => {
    store.insertPolicy(makePolicy({ id: "p1", secret_id: "s1", principal_id: "alpha" }));
    store.insertPolicy(
      makePolicy({
        id: "p2",
        secret_id: "s2",
        principal_id: "alpha",
        expires_at: NOW + 60_000,
      }),
    );
    store.insertPolicy(
      makePolicy({ id: "p3", secret_id: "s1", principal_id: "alpha", expires_at: NOW - 1 }),
    );
    store.insertPolicy(makePolicy({ id: "p4", secret_id: "s1", principal_id: "beta" }));

    expect(store.countActivePoliciesForPrincipal("agent", "alpha", NOW)).toBe(2);
    expect(store.countActivePoliciesForPrincipal("agent", "alpha", NOW + 120_000)).toBe(1);
    expect(store.countActivePoliciesForPrincipal("agent", "beta", NOW)).toBe(1);
    expect(store.countActivePoliciesForPrincipal("tool", "alpha", NOW)).toBe(0);
  });
});

describe("queryAuditLog principal filter", () => {
  beforeEach(() => {
    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW + 1 }), LINK);
    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW + 2, success: false }), LINK);
    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW + 3, principal_id: "beta" }), LINK);
    store.insertAuditEvent(
      makeAuditEvent({ timestamp: NOW + 4, principal_type: "tool", principal_id: "alpha" }),
      LINK,
    );
  });

  it("filters by principal id", () => {
    const rows = store.queryAuditLog({ principalId: "alpha" });
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r.principal_id === "alpha")).toBe(true);
  });

  it("filters by principal type", () => {
    const rows = store.queryAuditLog({ principalType: "tool" });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.principal_id).toBe("alpha");
  });

  it("composes principal type, principal id and success", () => {
    const rows = store.queryAuditLog({
      principalType: "agent",
      principalId: "alpha",
      success: false,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.timestamp).toBe(NOW + 2);

    const successes = store.queryAuditLog({
      principalType: "agent",
      principalId: "alpha",
      success: true,
    });
    expect(successes.map((r) => r.timestamp)).toEqual([NOW + 1]);
  });

  it("returns every row when no principal filter is set", () => {
    expect(store.queryAuditLog({})).toHaveLength(4);
  });
});
