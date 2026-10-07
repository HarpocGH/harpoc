import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, Permission, PrincipalType } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine;

const VALUE = new Uint8Array(Buffer.from("lifecycle-secret", "utf8"));

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function agent(id: string): CallerContext {
  return { principal_type: "agent", principal_id: id, interface: "rest" };
}

async function makeSecret(name: string): Promise<string> {
  await engine.createSecret({ name, type: SecretType.API_KEY, value: VALUE });
  return engine.resolveSecretId(`secret://${name}`);
}

function grant(secretId: string, principalId: string, permissions: Permission[]): void {
  registerAgents(engine, principalId);
  engine.grantPolicy(
    {
      secretId,
      principalType: "agent" as PrincipalType,
      principalId,
      permissions,
    },
    "test",
  );
}

function readsFor(secretId: string) {
  return engine.queryAudit({ eventType: AuditEventType.SECRET_READ, secretId });
}

// E75a: the config getters audited only the denial; getSecretInfo audits the
// grant too. Every read that audits a denial as `secret.read { config }` now
// audits the grant — the same row, unconditionally (a caller-less read leaves
// the NULL-principal trace `harpoc secret info` leaves).
describe("a granted configuration read is audited (E75a)", () => {
  interface ReadCase {
    name: string;
    config: string;
    read: (handle: string, secretId: string, caller?: CallerContext) => Promise<unknown>;
  }
  const CASES: ReadCase[] = [
    {
      name: "getInjectionPolicy",
      config: "injection",
      read: (h, _id, c) => engine.getInjectionPolicy(h, c),
    },
    {
      name: "getMcpServerConfig",
      config: "mcp_server",
      read: (h, _id, c) => engine.getMcpServerConfig(h, c),
    },
    {
      name: "getConnectionConfig",
      config: "connection",
      read: (h, _id, c) => engine.getConnectionConfig(h, c),
    },
    {
      name: "listPolicies",
      config: "access_policies",
      read: (h, id, c) => Promise.resolve(engine.listPolicies(id, c, h)),
    },
  ];

  it.each(CASES)(
    "$name: one success row naming the config, attributed to the reader",
    async ({ config, read }) => {
      const id = await makeSecret(`cfg-${config}`);
      grant(id, "alice", ["read"]);

      await read(`secret://cfg-${config}`, id, agent("alice"));

      const rows = readsFor(id).filter((r) => r.success);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.principal_id).toBe("alice");
      expect(rows[0]?.detail).toMatchObject({ config, interface: "rest" });
      expect(rows[0]?.detail?.action).toBeUndefined();
      expect(rows[0]?.detail?.required_permission).toBeUndefined();
    },
  );

  it.each(CASES)(
    "$name: the trusted path leaves the same row with a NULL principal",
    async ({ config, read }) => {
      const id = await makeSecret(`cfg-local-${config}`);

      await read(`secret://cfg-local-${config}`, id, undefined);

      const rows = readsFor(id).filter((r) => r.success);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.principal_type).toBeNull();
      expect(rows[0]?.detail).toMatchObject({ config });
      expect(rows[0]?.detail?.interface).toBeUndefined();
    },
  );

  it.each(CASES)("$name: a refused read writes only the denial", async ({ config, read }) => {
    const id = await makeSecret(`cfg-refused-${config}`);
    grant(id, "alice", ["list"]);

    await expectVaultError(
      () => read(`secret://cfg-refused-${config}`, id, agent("alice")),
      ErrorCode.ACCESS_DENIED,
    );

    expect(readsFor(id).filter((r) => r.success)).toHaveLength(0);
    expect(readsFor(id).filter((r) => !r.success)).toHaveLength(1);
  });

  it("the success detail is the denial detail minus required_permission and error", async () => {
    const id = await makeSecret("cfg-shape");
    grant(id, "alice", ["read"]);
    await engine.getInjectionPolicy("secret://cfg-shape", agent("alice"));
    grant(id, "bob", ["list"]);
    await expectVaultError(
      () => engine.getInjectionPolicy("secret://cfg-shape", agent("bob")),
      ErrorCode.ACCESS_DENIED,
    );

    const success = readsFor(id).find((r) => r.success);
    const denial = readsFor(id).find((r) => !r.success);
    expect(success?.detail).toEqual({
      handle: "secret://cfg-shape",
      config: "injection",
      interface: "rest",
    });
    expect(denial?.detail).toEqual({
      handle: "secret://cfg-shape",
      config: "injection",
      required_permission: "read",
      error: ErrorCode.ACCESS_DENIED,
      interface: "rest",
    });
  });

  it("getOAuthTokenStatus: the row follows a successful status read", async () => {
    const { secretId } = await engine.createOAuthSecret("oauth-cfg", {
      provider: "github",
      grant_type: "authorization_code",
      token_endpoint: "https://example.invalid/token",
      auth_endpoint: "https://example.invalid/authorize",
      client_id: "client-id",
      client_secret: "client-secret",
      scopes: ["repo"],
    });
    grant(secretId, "alice", ["read"]);

    engine.getOAuthTokenStatus(secretId, agent("alice"), "secret://oauth-cfg");

    const rows = readsFor(secretId).filter((r) => r.success);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toEqual({
      config: "oauth_status",
      interface: "rest",
    });
  });

  it("a read that throws after the gate writes no success row", async () => {
    const id = await makeSecret("no-cert");
    grant(id, "alice", ["read"]);

    await expectVaultError(
      () =>
        Promise.resolve().then(() =>
          engine.getCertificateStatus(id, agent("alice"), "secret://no-cert"),
        ),
      ErrorCode.CERT_NOT_CONFIGURED,
    );
    await expectVaultError(
      () =>
        Promise.resolve().then(() =>
          engine.getCertificatePem(id, agent("alice"), "secret://no-cert"),
        ),
      ErrorCode.CERT_NOT_CONFIGURED,
    );

    expect(readsFor(id).filter((r) => r.success)).toHaveLength(0);
  });
});

// E75a fallout: `listPolicies(secretId)` writes a row on every call, so the
// caller-less membership guard the REST and CLI revoke paths ran left a
// NULL-principal `secret.read` row beside their attributed `policy.revoke`.
// The check moved into the engine, where the expected secret id is a parameter.
describe("revokePolicy's membership check is inside the engine (E75a fallout)", () => {
  async function policyOn(name: string): Promise<{ secretId: string; policyId: string }> {
    const secretId = await makeSecret(name);
    registerAgents(engine, "alice");
    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent" as PrincipalType,
        principalId: "alice",
        permissions: ["read"] as Permission[],
      },
      "test",
    );
    return { secretId, policyId: policy.id };
  }

  it("a cross-secret expected id refuses exactly like an unknown policy id", async () => {
    const { secretId: idA, policyId } = await policyOn("policy-scope-a");
    const idB = await makeSecret("policy-scope-b");

    await expectVaultError(
      () => Promise.resolve().then(() => engine.revokePolicy(policyId, undefined, idB)),
      ErrorCode.POLICY_NOT_FOUND,
    );
    expect(engine.listPolicies(idA).some((p) => p.id === policyId)).toBe(true);
  });

  it("a caller admin on its own secret probing another secret's policy id is refused before the caller check — no row names the probe", async () => {
    const { secretId: idA, policyId } = await policyOn("policy-scope-probed");
    const idB = await makeSecret("policy-scope-own");
    grant(idB, "mallory", ["admin"]);

    const err = await expectVaultError(
      () => Promise.resolve().then(() => engine.revokePolicy(policyId, agent("mallory"), idB)),
      ErrorCode.POLICY_NOT_FOUND,
    );
    expect(err.message).toBe(`Policy not found: ${policyId}`);
    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE })).toHaveLength(0);
    expect(engine.listPolicies(idA).some((p) => p.id === policyId)).toBe(true);
  });

  it("the matching expected id revokes", async () => {
    const { secretId: idA, policyId } = await policyOn("policy-scope-match");

    engine.revokePolicy(policyId, undefined, idA);

    expect(engine.listPolicies(idA).some((p) => p.id === policyId)).toBe(false);
  });

  it("the parameter is optional — an unexpecting caller still revokes", async () => {
    const { secretId: idA, policyId } = await policyOn("policy-scope-optional");

    engine.revokePolicy(policyId, undefined);

    expect(engine.listPolicies(idA).some((p) => p.id === policyId)).toBe(false);
  });
});
