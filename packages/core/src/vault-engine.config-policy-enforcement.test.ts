import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, McpServerConfig, Permission, PrincipalType } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

/**
 * W1: secret-scoped *configuration* under the per-secret policy layer.
 *
 * V1 gated the six credential operations; the config operations stayed on
 * token scope alone, so a principal denied `rotate` could still rewrite the
 * allowlists that bound where the credential may be injected, and a principal
 * denied `read` could still read them. Read → `read`, mutate → `rotate`,
 * policy grant/revoke → `admin`, all presence-gated exactly like V1.
 */

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

const MCP_CONFIG: McpServerConfig = {
  server_name: "docs",
  transport: "http",
  url: "https://mcp.example.com/mcp",
};

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-cpe-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

/**
 * Register the agent identities this suite mints tokens or grants for — the
 * v1.4 registration gate refuses an unregistered agent-typed principal.
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

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

function agent(id: string, project?: string): CallerContext {
  const caller: CallerContext = { principal_type: "agent", principal_id: id, interface: "rest" };
  if (project) caller.project = project;
  return caller;
}

async function makeSecret(name: string): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from("value", "utf8")),
  });
  return engine.resolveSecretId(`secret://${name}`);
}

function grant(
  secretId: string,
  principalType: PrincipalType,
  principalId: string,
  permissions: Permission[],
  expiresAt?: number,
): void {
  if (principalType === "agent") registerAgents(principalId);
  engine.grantPolicy({ secretId, principalType, principalId, permissions, expiresAt }, "admin");
}

async function expectDenied(promise: Promise<unknown> | (() => unknown)): Promise<void> {
  try {
    await (typeof promise === "function" ? promise() : promise);
    expect.fail("expected ACCESS_DENIED");
  } catch (e) {
    expect(e).toBeInstanceOf(VaultError);
    expect((e as VaultError).code).toBe(ErrorCode.ACCESS_DENIED);
  }
}

/** Every config read + mutation, driven with one caller. */
async function readAll(handle: string, caller?: CallerContext): Promise<void> {
  await engine.getInjectionPolicy(handle, caller);
  await engine.getMcpServerConfig(handle, caller);
  await engine.getConnectionConfig(handle, caller);
}

async function mutateAll(handle: string, caller?: CallerContext): Promise<void> {
  await engine.setInjectionPolicy(handle, { url_allowlist: ["https://ok.example/*"] }, {}, caller);
  await engine.setMcpServerConfig(handle, MCP_CONFIG, caller);
  await engine.deleteMcpServerConfig(handle, caller);
  await engine.setConnectionConfig(handle, { database: { tls_mode: "require" } }, caller);
  await engine.deleteConnectionConfig(handle, caller);
}

describe("presence gate", () => {
  it("a secret without policy rows: every config op passes for a token caller", async () => {
    const handle = "secret://open";
    await makeSecret("open");
    const caller = agent("anyone");

    await expect(readAll(handle, caller)).resolves.toBeUndefined();
    await expect(mutateAll(handle, caller)).resolves.toBeUndefined();
  });

  it("a secret with policy rows restricts the config ops", async () => {
    const id = await makeSecret("gated");
    grant(id, "agent", "alice", ["use"]);
    const bob = agent("bob");

    await expectDenied(engine.getInjectionPolicy("secret://gated", bob));
    await expectDenied(engine.getMcpServerConfig("secret://gated", bob));
    await expectDenied(engine.getConnectionConfig("secret://gated", bob));
    await expectDenied(
      engine.setInjectionPolicy("secret://gated", { url_allowlist: ["*"] }, {}, bob),
    );
    await expectDenied(engine.setMcpServerConfig("secret://gated", MCP_CONFIG, bob));
    await expectDenied(engine.deleteMcpServerConfig("secret://gated", bob));
    await expectDenied(engine.setConnectionConfig("secret://gated", {}, bob));
    await expectDenied(engine.deleteConnectionConfig("secret://gated", bob));
    await expectDenied(() => engine.listPolicies(id, bob));
  });

  it("expired rows neither grant nor gate", async () => {
    const id = await makeSecret("expired-rows");
    grant(id, "agent", "alice", ["admin"], Date.now() - 1000);

    // No *active* row ⇒ presence gate off ⇒ any caller proceeds.
    await expect(readAll("secret://expired-rows", agent("bob"))).resolves.toBeUndefined();
    await expect(mutateAll("secret://expired-rows", agent("bob"))).resolves.toBeUndefined();
  });

  it("the trusted local path (no caller) is never checked", async () => {
    const id = await makeSecret("trusted");
    grant(id, "agent", "alice", ["use"]);

    await expect(readAll("secret://trusted")).resolves.toBeUndefined();
    await expect(mutateAll("secret://trusted")).resolves.toBeUndefined();
    expect(engine.listPolicies(id)).toHaveLength(1);
  });
});

describe("permission granularity (D2: read→read, mutate→rotate)", () => {
  it("a read grant opens the config reads but not the mutations", async () => {
    const id = await makeSecret("read-only");
    grant(id, "agent", "reader", ["read"]);
    const reader = agent("reader");

    await expect(readAll("secret://read-only", reader)).resolves.toBeUndefined();
    expect(engine.listPolicies(id, reader)).toHaveLength(1);

    await expectDenied(
      engine.setInjectionPolicy("secret://read-only", { url_allowlist: ["*"] }, {}, reader),
    );
    await expectDenied(engine.setMcpServerConfig("secret://read-only", MCP_CONFIG, reader));
    await expectDenied(engine.setConnectionConfig("secret://read-only", {}, reader));
    await expectDenied(engine.deleteMcpServerConfig("secret://read-only", reader));
    await expectDenied(engine.deleteConnectionConfig("secret://read-only", reader));
  });

  it("a rotate grant opens the mutations but not the reads", async () => {
    const id = await makeSecret("rotate-only");
    grant(id, "agent", "rotator", ["rotate"]);
    const rotator = agent("rotator");

    await expect(mutateAll("secret://rotate-only", rotator)).resolves.toBeUndefined();

    await expectDenied(engine.getInjectionPolicy("secret://rotate-only", rotator));
    await expectDenied(engine.getConnectionConfig("secret://rotate-only", rotator));
    await expectDenied(() => engine.listPolicies(id, rotator));
  });

  it("admin implies read and rotate on the config surface", async () => {
    const id = await makeSecret("admin-grant");
    grant(id, "agent", "root", ["admin"]);
    const root = agent("root");

    await expect(readAll("secret://admin-grant", root)).resolves.toBeUndefined();
    await expect(mutateAll("secret://admin-grant", root)).resolves.toBeUndefined();
    expect(engine.listPolicies(id, root)).toHaveLength(1);
  });

  it("a project-derived principal is honored on config ops", async () => {
    const id = await makeSecret("project-scoped");
    grant(id, "project", "api", ["rotate"]);

    await expect(
      engine.setInjectionPolicy(
        "secret://project-scoped",
        { url_allowlist: ["https://api.example/*"] },
        {},
        agent("any-agent", "api"),
      ),
    ).resolves.toBeUndefined();
    await expectDenied(
      engine.setInjectionPolicy("secret://project-scoped", {}, {}, agent("any-agent", "other")),
    );
  });
});

describe("policy administration (D3: grant/revoke require admin)", () => {
  it("the first grant is ungated, later ones require an admin grant", async () => {
    const id = await makeSecret("bootstrap");
    const bob = agent("bob");
    registerAgents("alice", "bob");

    // No rows yet ⇒ presence gate off.
    expect(() =>
      engine.grantPolicy(
        { secretId: id, principalType: "agent", principalId: "alice", permissions: ["use"] },
        "bob",
        bob,
      ),
    ).not.toThrow();

    // A row now exists and bob holds no admin grant.
    expect(() =>
      engine.grantPolicy(
        { secretId: id, principalType: "agent", principalId: "bob", permissions: ["admin"] },
        "bob",
        bob,
      ),
    ).toThrow(VaultError);
  });

  it("self-escalation is refused: a use-only principal cannot grant itself admin", async () => {
    const id = await makeSecret("no-escalation");
    grant(id, "agent", "bob", ["use"]);

    await expectDenied(() =>
      engine.grantPolicy(
        { secretId: id, principalType: "agent", principalId: "bob", permissions: ["admin"] },
        "bob",
        agent("bob"),
      ),
    );
    expect(engine.listPolicies(id)).toHaveLength(1);
  });

  it("revoking another principal's grant requires admin", async () => {
    const id = await makeSecret("revoke-gate");
    grant(id, "agent", "alice", ["use"]);
    const [aliceRow] = engine.listPolicies(id);

    await expectDenied(() => engine.revokePolicy(aliceRow?.id as string, agent("bob")));
    expect(engine.listPolicies(id)).toHaveLength(1);

    grant(id, "agent", "root", ["admin"]);
    engine.revokePolicy(aliceRow?.id as string, agent("root"));
    expect(engine.listPolicies(id).map((p) => p.principal_id)).toEqual(["root"]);
  });

  it("revokePolicy stamps the secret on its audit row", async () => {
    const id = await makeSecret("revoke-attrib");
    grant(id, "agent", "alice", ["use"]);
    const [row] = engine.listPolicies(id);
    engine.revokePolicy(row?.id as string);

    const revokes = engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE });
    expect(revokes.at(-1)?.secret_id).toBe(id);
  });

  it("an unknown policy id is POLICY_NOT_FOUND", async () => {
    expect(() => engine.revokePolicy("no-such-policy")).toThrow(
      expect.objectContaining({ code: ErrorCode.POLICY_NOT_FOUND }),
    );
  });

  it("listPolicies without a secret id is refused for a token caller (D6)", async () => {
    expect(() => engine.listPolicies(undefined, agent("bob"))).toThrow(
      expect.objectContaining({ code: ErrorCode.INVALID_INPUT }),
    );
    // The trusted path keeps the vault-wide listing.
    expect(() => engine.listPolicies()).not.toThrow();
  });
});

describe("denial ordering (D4: nothing happens before the check)", () => {
  it("a denied setInjectionPolicy writes no policy and skips the interpreter gate", async () => {
    const id = await makeSecret("ordering");
    await engine.setInjectionPolicy("secret://ordering", {
      url_allowlist: ["https://original.example/*"],
    });
    grant(id, "agent", "alice", ["use"]);

    await expectDenied(
      engine.setInjectionPolicy(
        "secret://ordering",
        { url_allowlist: ["https://evil.example/*"], command_allowlist: ["/usr/bin/bash"] },
        {},
        agent("bob"),
      ),
    );

    // Stored policy untouched (read via the trusted path).
    const stored = await engine.getInjectionPolicy("secret://ordering");
    expect(stored.url_allowlist).toEqual(["https://original.example/*"]);
    expect(stored.command_allowlist).toEqual([]);
    // The interpreter gate sits *after* the caller check — no refusal row.
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_REFUSED }),
    ).toHaveLength(0);
  });

  it("a denied mcp-server mutation never reaches the connection registry", async () => {
    const id = await makeSecret("registry");
    await engine.setMcpServerConfig("secret://registry", MCP_CONFIG);
    grant(id, "agent", "alice", ["use"]);

    // terminate() kills a live downstream child. A denied caller reaching it
    // would have a repeatable DoS against another principal's session, so the
    // check must sit ahead of it — spied directly, not inferred from audit.
    const registry = (engine as unknown as { mcpRegistry: { terminate: () => Promise<void> } })
      .mcpRegistry;
    const terminate = vi.spyOn(registry, "terminate");

    await expectDenied(engine.setMcpServerConfig("secret://registry", MCP_CONFIG, agent("bob")));
    await expectDenied(engine.deleteMcpServerConfig("secret://registry", agent("bob")));

    expect(terminate).not.toHaveBeenCalled();
    await expect(engine.getMcpServerConfig("secret://registry")).resolves.toMatchObject({
      server_name: "docs",
    });
  });
});

describe("audit attribution", () => {
  it("a denied config mutation is audited with principal, permission and interface", async () => {
    const id = await makeSecret("denial-row");
    grant(id, "agent", "alice", ["use"]);

    await expectDenied(engine.setInjectionPolicy("secret://denial-row", {}, {}, agent("bob")));

    const rows = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT, secretId: id });
    const denial = rows.find((r) => !r.success);
    expect(denial?.principal_type).toBe("agent");
    expect(denial?.principal_id).toBe("bob");
    expect(denial?.detail?.policy).toBe("injection");
    expect(denial?.detail?.required_permission).toBe("rotate");
    expect(denial?.detail?.error).toBe(ErrorCode.ACCESS_DENIED);
    expect(denial?.detail?.interface).toBe("rest");
  });

  it("a denied config read is audited as secret.read naming the config", async () => {
    const id = await makeSecret("read-denial-row");
    grant(id, "agent", "alice", ["use"]);

    await expectDenied(engine.getConnectionConfig("secret://read-denial-row", agent("bob")));

    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_READ, secretId: id });
    const denial = rows.find((r) => !r.success);
    expect(denial?.detail?.config).toBe("connection");
    expect(denial?.detail?.required_permission).toBe("read");
    expect(denial?.principal_id).toBe("bob");
  });

  it("an allowed config mutation carries the principal on its success row", async () => {
    const id = await makeSecret("success-row");
    grant(id, "agent", "alice", ["rotate"]);

    await engine.setConnectionConfig(
      "secret://success-row",
      { database: { tls_mode: "require" } },
      agent("alice"),
    );

    const rows = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT, secretId: id });
    const success = rows.filter((r) => r.success && r.detail?.policy === "connection");
    expect(success).toHaveLength(1);
    expect(success[0]?.principal_id).toBe("alice");
    expect(success[0]?.detail?.interface).toBe("rest");
  });

  it("the trusted path leaves the principal columns NULL", async () => {
    const id = await makeSecret("local-row");
    await engine.setConnectionConfig("secret://local-row", {});

    const rows = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT, secretId: id });
    const local = rows.filter((r) => r.detail?.policy === "connection");
    expect(local[0]?.principal_id).toBeNull();
    expect(local[0]?.detail?.interface).toBeUndefined();
  });

  it("the audit chain stays valid across denied and allowed config operations", async () => {
    const id = await makeSecret("chain");
    grant(id, "agent", "alice", ["rotate"]);

    await expectDenied(engine.setInjectionPolicy("secret://chain", {}, {}, agent("bob")));
    await engine.setInjectionPolicy("secret://chain", {}, {}, agent("alice"));
    await expectDenied(engine.getInjectionPolicy("secret://chain", agent("bob")));

    expect(engine.verifyAuditChain().valid).toBe(true);
  });
});
