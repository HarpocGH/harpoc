import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AccessPolicy, AuditEvent, Secret } from "@harpoc/shared";
import {
  AGENT_DESCRIPTION_MAX_LENGTH,
  AGENT_OWNER_MAX_LENGTH,
  AuditEventType,
  ErrorCode,
  MAX_NAME_LENGTH,
  SecretStatus,
  SecretType,
  VaultError,
} from "@harpoc/shared";
import type { IssuedTokenRow } from "../storage/sqlite-store.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { AgentRegistry } from "./agent-registry.js";

let store: SqliteStore;
let registry: AgentRegistry;

const NOW = 1_800_000_000_000;

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
    sync_version: 0,
    name_hmac: `hmac-${id}`,
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

function makeToken(agentId: string, overrides: Partial<IssuedTokenRow> = {}): IssuedTokenRow {
  return {
    jti: "jti-1",
    subject: "alpha",
    principal_type: "agent",
    agent_id: agentId,
    scope: ["read"],
    project: null,
    secrets: null,
    label: null,
    issued_at: NOW,
    expires_at: NOW + 60_000,
    revoked_at: null,
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

function expectCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
    expect.fail(`expected ${code}`);
  } catch (err) {
    expect(err).toBeInstanceOf(VaultError);
    expect((err as VaultError).code).toBe(code);
  }
}

beforeEach(() => {
  store = new SqliteStore(":memory:");
  registry = new AgentRegistry(store);
  store.insertSecret(makeSecret("s1"));
  store.insertSecret(makeSecret("s2"));
});

afterEach(() => {
  store.close();
});

describe("register", () => {
  it("stores an active agent with the supplied metadata and generated id", () => {
    const row = registry.register({ name: "alpha", description: "build bot", owner: "ops" }, NOW);

    expect(row).toMatchObject({
      name: "alpha",
      description: "build bot",
      owner: "ops",
      status: "active",
      created_at: NOW,
      updated_at: NOW,
      deactivated_at: null,
    });
    expect(row.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(store.getAgentByName("alpha")).toEqual(row);
  });

  it("defaults the two optional metadata fields to null", () => {
    const row = registry.register({ name: "alpha" }, NOW);
    expect(row.description).toBeNull();
    expect(row.owner).toBeNull();
  });

  it("refuses a name violating the shared name rule", () => {
    expectCode(() => registry.register({ name: "bad name" }), ErrorCode.INVALID_INPUT);
    expectCode(() => registry.register({ name: "" }), ErrorCode.INVALID_INPUT);
    expectCode(
      () => registry.register({ name: "a".repeat(MAX_NAME_LENGTH + 1) }),
      ErrorCode.INVALID_INPUT,
    );
  });

  it("refuses an over-long description or owner (the whole input is schema-validated)", () => {
    expectCode(
      () =>
        registry.register({
          name: "alpha",
          description: "d".repeat(AGENT_DESCRIPTION_MAX_LENGTH + 1),
        }),
      ErrorCode.INVALID_INPUT,
    );
    expectCode(
      () => registry.register({ name: "alpha", owner: "o".repeat(AGENT_OWNER_MAX_LENGTH + 1) }),
      ErrorCode.INVALID_INPUT,
    );
    expect(store.listAgents("all")).toHaveLength(0);
  });

  it("names the offending field in the refusal message", () => {
    try {
      registry.register({ name: "bad name" });
      expect.fail("expected INVALID_INPUT");
    } catch (err) {
      expect((err as VaultError).message).toContain("name");
    }
  });

  it("maps a duplicate name to AGENT_EXISTS, whatever the existing status", () => {
    registry.register({ name: "alpha" }, NOW);
    expectCode(() => registry.register({ name: "alpha" }), ErrorCode.AGENT_EXISTS);

    registry.setStatus("alpha", "inactive", NOW);
    expectCode(() => registry.register({ name: "alpha" }), ErrorCode.AGENT_EXISTS);
  });
});

describe("lookup", () => {
  it("getByName returns the row and throws AGENT_NOT_FOUND for an unknown name", () => {
    const row = registry.register({ name: "alpha" }, NOW);
    expect(registry.getByName("alpha")).toEqual(row);
    expectCode(() => registry.getByName("missing"), ErrorCode.AGENT_NOT_FOUND);
  });

  it("findByName returns undefined instead of throwing", () => {
    expect(registry.findByName("missing")).toBeUndefined();
    registry.register({ name: "alpha" }, NOW);
    expect(registry.findByName("alpha")?.name).toBe("alpha");
  });

  it("list filters by status and 'all' includes both", () => {
    registry.register({ name: "alpha" }, NOW);
    registry.register({ name: "beta" }, NOW);
    registry.setStatus("beta", "inactive", NOW);

    expect(registry.list("active").map((a) => a.name)).toEqual(["alpha"]);
    expect(registry.list("inactive").map((a) => a.name)).toEqual(["beta"]);
    expect(registry.list("all").map((a) => a.name)).toEqual(["alpha", "beta"]);
  });
});

describe("assertActive", () => {
  it("returns the row for an active agent", () => {
    const row = registry.register({ name: "alpha" }, NOW);
    expect(registry.assertActive("alpha")).toEqual(row);
  });

  it("throws AGENT_NOT_FOUND for an unregistered name", () => {
    expectCode(() => registry.assertActive("missing"), ErrorCode.AGENT_NOT_FOUND);
  });

  it("throws AGENT_INACTIVE for a deactivated agent", () => {
    registry.register({ name: "alpha" }, NOW);
    registry.setStatus("alpha", "inactive", NOW);
    expectCode(() => registry.assertActive("alpha"), ErrorCode.AGENT_INACTIVE);
  });
});

describe("updateMetadata", () => {
  it("replaces both fields — an omitted field is cleared, not kept", () => {
    registry.register({ name: "alpha", description: "old", owner: "ops" }, NOW);

    const updated = registry.updateMetadata("alpha", { description: "new" }, NOW + 1000);

    expect(updated.description).toBe("new");
    expect(updated.owner).toBeNull();
    expect(updated.updated_at).toBe(NOW + 1000);
    expect(store.getAgentByName("alpha")).toEqual(updated);
  });

  it("clears both fields on an empty input", () => {
    registry.register({ name: "alpha", description: "old", owner: "ops" }, NOW);
    const updated = registry.updateMetadata("alpha", {}, NOW + 1000);
    expect(updated.description).toBeNull();
    expect(updated.owner).toBeNull();
  });

  it("leaves name and status untouched", () => {
    registry.register({ name: "alpha" }, NOW);
    registry.setStatus("alpha", "inactive", NOW);
    const updated = registry.updateMetadata("alpha", { owner: "ops" }, NOW + 1000);
    expect(updated.name).toBe("alpha");
    expect(updated.status).toBe("inactive");
  });

  it("validates the input and refuses an unknown agent", () => {
    registry.register({ name: "alpha" }, NOW);
    expectCode(
      () =>
        registry.updateMetadata("alpha", { owner: "o".repeat(AGENT_OWNER_MAX_LENGTH + 1) }, NOW),
      ErrorCode.INVALID_INPUT,
    );
    expectCode(() => registry.updateMetadata("missing", {}, NOW), ErrorCode.AGENT_NOT_FOUND);
  });
});

describe("setStatus", () => {
  it("stamps deactivated_at on deactivation and clears it on reactivation", () => {
    registry.register({ name: "alpha" }, NOW);

    const off = registry.setStatus("alpha", "inactive", NOW + 1000);
    expect(off.status).toBe("inactive");
    expect(off.deactivated_at).toBe(NOW + 1000);
    expect(off.updated_at).toBe(NOW + 1000);
    expect(store.getAgentByName("alpha")).toEqual(off);

    const on = registry.setStatus("alpha", "active", NOW + 2000);
    expect(on.status).toBe("active");
    expect(on.deactivated_at).toBeNull();
    expect(store.getAgentByName("alpha")).toEqual(on);
  });

  it("throws AGENT_NOT_FOUND for an unknown agent", () => {
    expectCode(() => registry.setStatus("missing", "inactive", NOW), ErrorCode.AGENT_NOT_FOUND);
  });
});

describe("delete", () => {
  it("removes the row and returns exactly what it removed", () => {
    const row = registry.register({ name: "alpha", owner: "ops" }, NOW);
    expect(registry.delete("alpha")).toEqual(row);
    expect(store.getAgentByName("alpha")).toBeUndefined();
  });

  it("throws AGENT_NOT_FOUND for an unknown agent", () => {
    expectCode(() => registry.delete("missing"), ErrorCode.AGENT_NOT_FOUND);
  });
});

describe("toAgent", () => {
  it("derives last_active_at, active_tokens and grants", () => {
    const row = registry.register({ name: "alpha", owner: "ops" }, NOW);
    const other = registry.register({ name: "beta" }, NOW);

    store.insertIssuedToken(makeToken(row.id, { jti: "live-1" }));
    store.insertIssuedToken(makeToken(row.id, { jti: "live-2" }));
    store.insertIssuedToken(makeToken(row.id, { jti: "expired", expires_at: NOW - 1 }));
    store.insertIssuedToken(makeToken(row.id, { jti: "revoked", revoked_at: NOW }));
    store.insertIssuedToken(makeToken(other.id, { jti: "foreign", subject: "beta" }));

    store.insertPolicy(makePolicy({ id: "p1", secret_id: "s1" }));
    store.insertPolicy(makePolicy({ id: "p2", secret_id: "s2", expires_at: NOW + 60_000 }));
    store.insertPolicy(makePolicy({ id: "p3", secret_id: "s2", expires_at: NOW - 1 }));
    store.insertPolicy(makePolicy({ id: "p4", secret_id: "s1", principal_id: "beta" }));

    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW - 10_000 }));
    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW - 500 }));
    store.insertAuditEvent(makeAuditEvent({ timestamp: NOW - 100, principal_id: "beta" }));

    expect(registry.toAgent(row, NOW)).toEqual({
      ...row,
      last_active_at: NOW - 500,
      active_tokens: 2,
      grants: 2,
    });
  });

  it("reports zeroed derived fields for a fresh agent", () => {
    const row = registry.register({ name: "alpha" }, NOW);
    expect(registry.toAgent(row, NOW)).toEqual({
      ...row,
      last_active_at: null,
      active_tokens: 0,
      grants: 0,
    });
  });
});
