import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, Permission, PrincipalType, UseSecretAction } from "@harpoc/shared";
import {
  AuditEventType,
  ErrorCode,
  SecretType,
  tokenlessStdioCaller,
  VaultError,
} from "@harpoc/shared";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

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

/** The engine's live store (test seam — private field), for counting handle resolutions. */
function storeOf(e: VaultEngine): SqliteStore {
  return (e as unknown as { store: SqliteStore }).store;
}

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

  // D3: a probe through a route whose semantics are not a read left a
  // `secret.read` row, so `harpoc audit --event secret.read` showed six routes'
  // probes and `--event cert.renew` showed none of them.
  it("resolveSecretId carries the route's own event type into the failed row", async () => {
    await expectVaultError(
      () => engine.resolveSecretId(H, agent("bob"), AuditEventType.CERT_RENEW),
      ErrorCode.SECRET_NOT_FOUND,
    );

    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_READ })).toHaveLength(0);
    const row = engine.queryAudit({ eventType: AuditEventType.CERT_RENEW }).find((r) => !r.success);
    expect(row?.principal_id).toBe("bob");
    expect(row?.secret_id).toBeNull();
    expect(row?.detail).toEqual({
      handle: H,
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "rest",
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
    protocol: "2025-11-25",
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
      call: () =>
        engine.setConnectionConfig(H, { database: { tls_mode: "require" } }, agent("bob")),
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
      registerAgents(engine, "bob");
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
    registerAgents(engine, "bob");

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
    registerAgents(engine, "bob");
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

// R16(a): a caller-ful wrapped method resolved the handle twice — once in
// `enforceCallerPolicy`, once inside the manager — so every `--allow-tokenless`
// stdio call paid a second name-HMAC lookup for a record it already held.
describe("the gate's resolved secret is reused by the wrapped method (R16)", () => {
  const REUSE: Array<{
    name: string;
    permission: Permission;
    call: (handle: string, caller: CallerContext) => Promise<unknown>;
  }> = [
    { name: "getSecretInfo", permission: "read", call: (h, c) => engine.getSecretInfo(h, c) },
    {
      name: "rotateSecret",
      permission: "rotate",
      call: (h, c) => engine.rotateSecret(h, VALUE, c),
    },
    { name: "revokeSecret", permission: "revoke", call: (h, c) => engine.revokeSecret(h, c) },
  ];

  it.each(REUSE)(
    "$name resolves the handle once, not twice",
    async ({ name, permission, call }) => {
      const id = await makeSecret(`reuse-${name}`);
      grant(id, "alice", [permission]);
      const spy = vi.spyOn(storeOf(engine), "getSecretsByNameHmac");

      await call(`secret://reuse-${name}`, agent("alice"));

      expect(spy).toHaveBeenCalledTimes(1);
      spy.mockRestore();
    },
  );
});

// R16(b): the vault-wide form refused every caller, so the synthetic
// `tokenless-stdio` caller lost a listing the absent caller it replaces had.
// It is an admin-user caller (R7); only a genuinely scoped token is refused.
describe("the vault-wide listPolicies form admits the admin-user classes (R16)", () => {
  it("the tokenless-stdio caller lists vault-wide and writes no row", async () => {
    const id = await makeSecret("vault-wide");
    grant(id, "alice", ["read"]);
    const before = engine.queryAudit({ eventType: AuditEventType.SECRET_READ }).length;

    const policies = engine.listPolicies(undefined, tokenlessStdioCaller("mcp"));

    expect(policies.map((p) => p.secret_id)).toEqual([id]);
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_READ })).toHaveLength(before);
  });

  it("a scoped token caller must still name the secret", async () => {
    await makeSecret("vault-wide-denied");
    const err = await expectVaultError(
      () => engine.listPolicies(undefined, agent("bob")),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe("A secret id is required to list access policies");
  });
});
