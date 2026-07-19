import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Secret } from "@harpoc/shared";
import { ErrorCode, SecretStatus, SecretType, VaultError } from "@harpoc/shared";
import { SqliteStore } from "../storage/sqlite-store.js";
import { PolicyEngine } from "./policy-engine.js";

let store: SqliteStore;
let engine: PolicyEngine;

function makeSecret(id: string): Secret {
  const now = Date.now();
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
    created_at: now,
    updated_at: now,
    expires_at: null,
    rotated_at: null,
    version: 1,
    status: SecretStatus.ACTIVE,
    sync_version: 0,
  };
}

beforeEach(() => {
  store = new SqliteStore(":memory:");
  engine = new PolicyEngine(store);

  // Insert test secrets
  store.insertSecret(makeSecret("s1"));
  store.insertSecret(makeSecret("s2"));
});

afterEach(() => {
  store.close();
});

describe("grantPolicy", () => {
  it("creates a policy with generated ID", () => {
    const policy = engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read", "use"],
      createdBy: "user",
    });

    expect(policy.id).toBeTruthy();
    expect(policy.secret_id).toBe("s1");
    expect(policy.permissions).toEqual(["read", "use"]);
    expect(policy.expires_at).toBeNull();
  });

  it("accepts an expiration time", () => {
    const future = Date.now() + 60_000;
    const policy = engine.grantPolicy({
      secretId: "s1",
      principalType: "tool",
      principalId: "tool-1",
      permissions: ["use"],
      expiresAt: future,
      createdBy: "admin",
    });

    expect(policy.expires_at).toBe(future);
  });
});

describe("revokePolicy", () => {
  it("deletes the policy", () => {
    const policy = engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read"],
      createdBy: "user",
    });

    engine.revokePolicy(policy.id);

    const policies = engine.listPolicies("s1");
    expect(policies.length).toBe(0);
  });

  it("throws POLICY_NOT_FOUND for missing policy", () => {
    try {
      engine.revokePolicy("nonexistent");
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VaultError);
      expect((e as VaultError).code).toBe(ErrorCode.POLICY_NOT_FOUND);
    }
  });
});

describe("listPolicies", () => {
  it("lists all non-expired policies for a secret", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read"],
      createdBy: "user",
    });
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-2",
      permissions: ["use"],
      createdBy: "user",
    });

    expect(engine.listPolicies("s1").length).toBe(2);
  });

  it("filters out expired policies", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read"],
      expiresAt: Date.now() - 1000, // expired
      createdBy: "user",
    });
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-2",
      permissions: ["use"],
      createdBy: "user",
    });

    expect(engine.listPolicies("s1").length).toBe(1);
  });

  it("lists policies across all secrets when no secretId given", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "a",
      permissions: ["read"],
      createdBy: "user",
    });
    engine.grantPolicy({
      secretId: "s2",
      principalType: "agent",
      principalId: "b",
      permissions: ["use"],
      createdBy: "user",
    });

    expect(engine.listPolicies().length).toBe(2);
  });
});

describe("checkPermission", () => {
  it("returns true when policy grants the permission", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read", "use"],
      createdBy: "user",
    });

    expect(engine.checkPermission("s1", "agent", "agent-1", "read")).toBe(true);
    expect(engine.checkPermission("s1", "agent", "agent-1", "use")).toBe(true);
  });

  it("returns false when permission not granted", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read"],
      createdBy: "user",
    });

    expect(engine.checkPermission("s1", "agent", "agent-1", "rotate")).toBe(false);
  });

  it("returns false for wrong secret", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read"],
      createdBy: "user",
    });

    expect(engine.checkPermission("s2", "agent", "agent-1", "read")).toBe(false);
  });

  it("admin implies all permissions", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "user",
      principalId: "admin-user",
      permissions: ["admin"],
      createdBy: "system",
    });

    expect(engine.checkPermission("s1", "user", "admin-user", "read")).toBe(true);
    expect(engine.checkPermission("s1", "user", "admin-user", "use")).toBe(true);
    expect(engine.checkPermission("s1", "user", "admin-user", "rotate")).toBe(true);
    expect(engine.checkPermission("s1", "user", "admin-user", "revoke")).toBe(true);
  });

  it("returns false for expired policy", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["read", "use"],
      expiresAt: Date.now() - 1000,
      createdBy: "user",
    });

    expect(engine.checkPermission("s1", "agent", "agent-1", "read")).toBe(false);
  });

  it("returns false for no policies", () => {
    expect(engine.checkPermission("s1", "agent", "unknown", "read")).toBe(false);
  });
});

describe("hasActivePolicies", () => {
  it("is false for a secret with no policy rows", () => {
    expect(engine.hasActivePolicies("s1")).toBe(false);
  });

  it("is true once an active row exists, and scoped to that secret", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["use"],
      createdBy: "user",
    });

    expect(engine.hasActivePolicies("s1")).toBe(true);
    expect(engine.hasActivePolicies("s2")).toBe(false);
  });

  it("is false when every row is expired (the gate reopens)", () => {
    engine.grantPolicy({
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      permissions: ["use"],
      expiresAt: Date.now() - 1000,
      createdBy: "user",
    });

    expect(engine.hasActivePolicies("s1")).toBe(false);
  });
});
