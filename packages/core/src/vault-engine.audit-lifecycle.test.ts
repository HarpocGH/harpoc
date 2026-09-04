import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, Permission, PrincipalType, UseSecretAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import type { McpConnectionEntry, McpConnectionRegistry } from "./injection/mcp-registry.js";
import { VaultEngine } from "./vault-engine.js";
import { expectVaultError } from "@harpoc/test-utils";

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

const NODE = process.execPath;
const VALUE = new Uint8Array(Buffer.from("lifecycle-secret", "utf8"));
const USE: UseSecretAction = {
  type: "process",
  command: NODE,
  args: ["-e", "process.exit(0)"],
  env_var: "SECRET",
};
const OPERATOR: CallerContext = {
  principal_type: "user",
  principal_id: "operator",
  interface: "rest",
  admin_scope: true,
};

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-alc-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

/**
 * Register the agent identities this suite grants for — the v1.4
 * registration gate refuses an unregistered agent-typed principal.
 */
function registerAgents(...names: string[]): void {
  for (const name of names) {
    try {
      engine.registerAgent({ name });
    } catch (err) {
      if (!(err instanceof VaultError) || err.code !== ErrorCode.AGENT_EXISTS) throw err;
    }
  }
}

function agent(id: string): CallerContext {
  return { principal_type: "agent", principal_id: id, interface: "rest" };
}

async function makeSecret(name: string): Promise<string> {
  await engine.createSecret({ name, type: SecretType.API_KEY, value: VALUE });
  return engine.resolveSecretId(`secret://${name}`);
}

function grant(secretId: string, principalId: string, permissions: Permission[]): void {
  registerAgents(principalId);
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

/** The engine's live MCP connection registry (test seam — private field). */
function registryOf(e: VaultEngine): McpConnectionRegistry {
  return (e as unknown as { mcpRegistry: McpConnectionRegistry }).mcpRegistry;
}

/** Publish a ready stdio entry without spawning a child — something live to tear down. */
async function seedLiveStdioEntry(secretId: string): Promise<void> {
  const client = { onclose: undefined, close: () => Promise.resolve() };
  await registryOf(engine).acquire(secretId, () =>
    Promise.resolve({
      secretId,
      serverName: "docs",
      transportKind: "stdio",
      client: client as unknown as McpConnectionEntry["client"],
      state: "connecting",
      crashed: false,
      credentialFingerprint: "cred-fp",
      configFingerprint: "config-fp",
      spawnedAt: Date.now(),
      lastUsedAt: Date.now(),
    } satisfies McpConnectionEntry),
  );
}

function readsFor(secretId: string) {
  return engine.queryAudit({ eventType: AuditEventType.SECRET_READ, secretId });
}

function terminatesFor(secretId: string) {
  return engine.queryAudit({
    eventType: AuditEventType.MCP_TERMINATE,
    secretId,
  });
}

// E73 (b): a token-level or policy-level refusal used to fire before the
// dispatch and never touch the registry, so a child spawned under a grant that
// has since been revoked kept the credential in its environment until the
// session ended. The refusal now ends the child.
describe("a denied use ends the secret's live downstream child (E73)", () => {
  it("ACCESS_DENIED for a list holder: the entry is terminated, reason use_denied, attributed", async () => {
    const id = await makeSecret("mcp-denied");
    grant(id, "alice", ["list"]);
    await seedLiveStdioEntry(id);

    await expectVaultError(
      () => engine.useSecret("secret://mcp-denied", USE, agent("alice")),
      ErrorCode.ACCESS_DENIED,
    );

    expect(registryOf(engine).get(id)).toBeUndefined();
    const [row] = terminatesFor(id);
    expect(row?.detail).toMatchObject({ reason: "use_denied", server: "docs" });
    expect(row?.principal_id).toBe("alice");
    expect(row?.detail?.interface).toBe("rest");
  });

  it("the concealed refusal (no grant at all) terminates too; the wire still reads not-found", async () => {
    const id = await makeSecret("mcp-concealed");
    await seedLiveStdioEntry(id);

    await expectVaultError(
      () => engine.useSecret("secret://mcp-concealed", USE, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );

    expect(registryOf(engine).get(id)).toBeUndefined();
    expect(terminatesFor(id)[0]?.principal_id).toBe("bob");
  });

  it("control: a use holder passes the gate and keeps the child", async () => {
    const id = await makeSecret("mcp-kept");
    grant(id, "alice", ["use"]);
    await seedLiveStdioEntry(id);

    // Past the gate the process context refuses on its empty command allowlist
    // — a refusal the registry never hears about.
    await expectVaultError(
      () => engine.useSecret("secret://mcp-kept", USE, agent("alice")),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );

    expect(registryOf(engine).get(id)).toBeDefined();
    expect(terminatesFor(id)).toHaveLength(0);
  });

  it("no live entry: the refusal writes no mcp.terminate row", async () => {
    const id = await makeSecret("mcp-nothing-live");
    await expectVaultError(
      () => engine.useSecret("secret://mcp-nothing-live", USE, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(terminatesFor(id)).toHaveLength(0);
  });
});

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

// Step-4 R-f residue: the routes that resolve a handle before an id-addressed
// call did so caller-less and unaudited, so an unknown-handle probe through
// them left no row where the same probe through the secrets routes left one.
describe("an unknown-handle probe is audited on every resolving surface", () => {
  const H = "secret://nope";

  it("resolveSecretId with a caller: a failed secret.read { handle } row, attributed", async () => {
    await expectVaultError(
      () => engine.resolveSecretId(H, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );

    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success);
    expect(row?.principal_id).toBe("bob");
    expect(row?.secret_id).toBeNull();
    expect(row?.detail).toEqual({
      handle: H,
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "rest",
    });
  });

  it("resolveSecretId on the trusted path: the same row with a NULL principal", async () => {
    await expectVaultError(() => engine.resolveSecretId(H), ErrorCode.SECRET_NOT_FOUND);
    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success);
    expect(row?.principal_type).toBeNull();
    expect(row?.detail).toEqual({
      handle: H,
      error: ErrorCode.SECRET_NOT_FOUND,
    });
  });

  interface ConfigSite {
    name: string;
    eventType: AuditEventType;
    detail: Record<string, unknown>;
    call: () => Promise<unknown>;
  }
  const MCP_CONFIG = {
    server_name: "docs",
    transport: "http",
    url: "https://mcp.example.com/mcp",
  } as const;
  const SITES: ConfigSite[] = [
    {
      name: "getInjectionPolicy",
      eventType: AuditEventType.SECRET_READ,
      detail: { handle: H, config: "injection" },
      call: () => engine.getInjectionPolicy(H, agent("bob")),
    },
    {
      name: "setInjectionPolicy",
      eventType: AuditEventType.POLICY_GRANT,
      detail: { handle: H, policy: "injection" },
      call: async () => {
        await makeSecret("policy-donor");
        const policy = await engine.getInjectionPolicy("secret://policy-donor");
        return engine.setInjectionPolicy(H, policy, undefined, agent("bob"));
      },
    },
    {
      name: "getMcpServerConfig",
      eventType: AuditEventType.SECRET_READ,
      detail: { handle: H, config: "mcp_server" },
      call: () => engine.getMcpServerConfig(H, agent("bob")),
    },
    {
      name: "setMcpServerConfig",
      eventType: AuditEventType.POLICY_GRANT,
      detail: { handle: H, policy: "mcp_server" },
      call: () => engine.setMcpServerConfig(H, MCP_CONFIG, agent("bob")),
    },
    {
      name: "deleteMcpServerConfig",
      eventType: AuditEventType.POLICY_REVOKE,
      detail: { handle: H, policy: "mcp_server" },
      call: () => engine.deleteMcpServerConfig(H, agent("bob")),
    },
    {
      name: "getConnectionConfig",
      eventType: AuditEventType.SECRET_READ,
      detail: { handle: H, config: "connection" },
      call: () => engine.getConnectionConfig(H, agent("bob")),
    },
    {
      name: "setConnectionConfig",
      eventType: AuditEventType.POLICY_GRANT,
      detail: { handle: H, policy: "connection" },
      call: () => engine.setConnectionConfig(H, {}, agent("bob")),
    },
    {
      name: "deleteConnectionConfig",
      eventType: AuditEventType.POLICY_REVOKE,
      detail: { handle: H, policy: "connection" },
      call: () => engine.deleteConnectionConfig(H, agent("bob")),
    },
  ];

  it.each(SITES)(
    "$name on an unknown handle writes its failed row before throwing",
    async ({ eventType, detail, call }) => {
      registerAgents("bob");
      await expectVaultError(call, ErrorCode.SECRET_NOT_FOUND);
      const row = engine
        .queryAudit({ eventType })
        .find((r) => !r.success && r.detail?.handle === H);
      expect(row?.principal_id).toBe("bob");
      expect(row?.detail).toEqual({
        ...detail,
        error: ErrorCode.SECRET_NOT_FOUND,
        interface: "rest",
      });
    },
  );
});

// R5 applied to ambiguity (ruled 2026-09-02): a bare name resolving to more
// than one secret — only possible once every match is revoked, since a second
// live secret of one name is refused at creation — answered 409 to any caller,
// telling a grantless token that two or more revoked secrets of that name
// existed where an unknown name says nothing.
describe("AMBIGUOUS_HANDLE is concealed for a grantless token caller", () => {
  const H = "secret://twice";

  /** Two revoked secrets named `twice`; alice holds `read` on the first. */
  async function makeAmbiguous(): Promise<void> {
    const first = await makeSecret("twice");
    grant(first, "alice", ["read"]);
    await engine.revokeSecret(H);
    await makeSecret("twice");
    await engine.revokeSecret(H);
  }

  it("a caller holding nothing on any candidate reads the byte-identical not-found; the row keeps the truth", async () => {
    await makeAmbiguous();
    registerAgents("bob");

    const err = await expectVaultError(
      () => engine.getSecretInfo(H, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(err.message).toBe(VaultError.secretNotFound(H).message);

    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success && r.principal_id === "bob");
    expect(row?.detail?.error).toBe(ErrorCode.AMBIGUOUS_HANDLE);
  });

  it("a candidate's grant holder, an admin-scoped user token and the trusted path keep 409", async () => {
    await makeAmbiguous();
    await expectVaultError(
      () => engine.getSecretInfo(H, agent("alice")),
      ErrorCode.AMBIGUOUS_HANDLE,
    );
    await expectVaultError(() => engine.getSecretInfo(H, OPERATOR), ErrorCode.AMBIGUOUS_HANDLE);
    await expectVaultError(() => engine.getSecretInfo(H), ErrorCode.AMBIGUOUS_HANDLE);
  });

  it("the rule holds on every concealment site a token caller reaches", async () => {
    await makeAmbiguous();
    registerAgents("bob");
    await expectVaultError(
      () => engine.resolveSecretId(H, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );
    await expectVaultError(
      () => engine.useSecret(H, USE, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );
    await expectVaultError(
      () => engine.getInjectionPolicy(H, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );
    await expectVaultError(
      () => engine.getSecretValue(H, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );
    await expectVaultError(
      () => engine.rotateSecret(H, VALUE, agent("bob")),
      ErrorCode.SECRET_NOT_FOUND,
    );
    await expectVaultError(() => engine.revokeSecret(H, agent("bob")), ErrorCode.SECRET_NOT_FOUND);
    await expectVaultError(
      () => engine.resolveSecretId(H, agent("alice")),
      ErrorCode.AMBIGUOUS_HANDLE,
    );
  });

  it("findByHandle returns the candidate set the resolver discards", async () => {
    await makeAmbiguous();
    const manager = (
      engine as unknown as {
        secretManager: { findByHandle(h: string): Promise<unknown[]> };
      }
    ).secretManager;
    expect((await manager.findByHandle(H)).length).toBe(2);
    expect((await manager.findByHandle("secret://nope")).length).toBe(0);
  });
});

// E75a fallout: `listPolicies(secretId)` writes a row on every call, so the
// caller-less membership guard the REST and CLI revoke paths ran left a
// NULL-principal `secret.read` row beside their attributed `policy.revoke`.
// The check moved into the engine, where the expected secret id is a parameter.
describe("revokePolicy's membership check is inside the engine (E75a fallout)", () => {
  async function policyOn(name: string): Promise<{ secretId: string; policyId: string }> {
    const secretId = await makeSecret(name);
    registerAgents("alice");
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
