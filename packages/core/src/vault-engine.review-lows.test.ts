import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import { SqliteStore } from "./storage/sqlite-store.js";
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

/**
 * Regression suite for the full-repository review's Low findings that live in
 * the engine: L2 (downstream teardown on revoke/expiry), L3 (create
 * attribution), L4 (secret_id on the lifecycle success rows), L5 (loadSession
 * version guard) and L10 (audit reads honour the token's project/name scope).
 */

const MCP_TEST_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "lows-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      content: [{ type: "text", text: process.env.DOWNSTREAM_TOKEN || "unset" }],
    }});
  }
});
`;

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

const VALUE = Buffer.from("super-secret-value", "utf8");

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-lows-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
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

async function makeSecret(name: string, project?: string, expiresAt?: number): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    project,
    value: new Uint8Array(VALUE),
    expiresAt,
  });
  return engine.resolveSecretId(project ? `secret://${project}/${name}` : `secret://${name}`);
}

/** Configure `handle` as a downstream stdio MCP server and spawn it. */
async function spawnDownstream(handle: string, serverName: string): Promise<void> {
  await engine.setInjectionPolicy(
    handle,
    { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
    { acknowledge_interpreters: true },
  );
  await engine.setMcpServerConfig(handle, {
    server_name: serverName,
    transport: "stdio",
    command: process.execPath,
    args: ["-e", MCP_TEST_SERVER],
    env_var: "DOWNSTREAM_TOKEN",
  });
  await engine.useSecret(handle, { type: "mcp", server: serverName, tool: "leak" });
}

function terminateRows(): { secretId: string | null; reason: unknown }[] {
  return engine
    .queryAudit({ eventType: AuditEventType.MCP_TERMINATE })
    .map((row) => ({ secretId: row.secret_id, reason: row.detail?.reason }));
}

// ---------------------------------------------------------------------------
// L4 — the six credential-lifecycle success rows carry secret_id
// ---------------------------------------------------------------------------

describe("L4 — lifecycle success rows are addressable by secret_id", () => {
  it("stamps secret_id on create, read, get_value, set, rotate and revoke", async () => {
    await engine.createSecret({ name: "pending-key", type: SecretType.API_KEY });
    const pendingId = await engine.resolveSecretId("secret://pending-key");
    await engine.setSecretValue("secret://pending-key", new Uint8Array(VALUE));

    const id = await makeSecret("lifecycle");
    await engine.getSecretInfo("secret://lifecycle");
    await engine.getSecretValue("secret://lifecycle");
    await engine.rotateSecret("secret://lifecycle", new Uint8Array(Buffer.from("rotated")));
    await engine.revokeSecret("secret://lifecycle");

    // The whole point of the finding: `audit --secret <id>` used to omit
    // exactly the successful reads/rotations/revocations of that secret.
    const scoped = engine.queryAudit({ secretId: id });
    const types = scoped.filter((r) => r.success).map((r) => r.event_type);
    expect(types).toContain(AuditEventType.SECRET_CREATE);
    expect(types).toContain(AuditEventType.SECRET_READ);
    expect(types).toContain(AuditEventType.SECRET_ROTATE);
    expect(types).toContain(AuditEventType.SECRET_REVOKE);
    // Two reads: getSecretInfo and getSecretValue.
    expect(scoped.filter((r) => r.event_type === AuditEventType.SECRET_READ)).toHaveLength(2);

    const setRow = engine
      .queryAudit({ secretId: pendingId })
      .find((r) => r.detail?.action === "set_value");
    expect(setRow).toBeDefined();
  });

  it("stamps secret_id on a denial row once the handle resolved", async () => {
    const id = await makeSecret("denied-read");
    await engine.revokeSecret("secret://denied-read");

    await expect(engine.getSecretValue("secret://denied-read")).rejects.toMatchObject({
      code: ErrorCode.SECRET_REVOKED,
    });

    const denial = engine
      .queryAudit({ secretId: id })
      .find((r) => !r.success && r.event_type === AuditEventType.SECRET_READ);
    expect(denial).toBeDefined();
    expect(denial?.detail?.error).toBe(ErrorCode.SECRET_REVOKED);
  });

  it("negative control: an unresolvable handle still audits without a secret_id", async () => {
    await expect(engine.getSecretInfo("secret://ghost")).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });
    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success);
    expect(row?.secret_id).toBeNull();
  });

  // The three denial arms that pass no resolved id at all: nothing resolved, so
  // NULL is the honest column value — and a later refactor that reaches for a
  // "nearby" id instead would mis-attribute a row about a secret that was never
  // found.

  it("a failed revoke of an unresolvable handle audits with secret_id null", async () => {
    await expect(engine.revokeSecret("secret://ghost")).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });

    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_REVOKE })
      .find((r) => !r.success);
    expect(row).toBeDefined();
    expect(row?.secret_id).toBeNull();
  });

  it("a failed useSecret handle resolution audits with secret_id null", async () => {
    await expect(
      engine.useSecret("secret://ghost", {
        type: "http",
        method: "GET",
        url: "https://example.invalid/",
        injection: { type: "bearer" },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.SECRET_NOT_FOUND });

    const row = engine.queryAudit({ eventType: AuditEventType.SECRET_USE }).find((r) => !r.success);
    expect(row).toBeDefined();
    expect(row?.secret_id).toBeNull();
  });

  it("a caller-present unresolvable handle audits the policy denial with secret_id null", async () => {
    // With a caller the refusal happens one layer earlier, in
    // enforceCallerPolicy's own resolution attempt — a different auditDenied
    // call site from the negative control above.
    await expect(engine.getSecretInfo("secret://ghost", agent("mallory"))).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });

    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => !r.success);
    expect(row).toBeDefined();
    expect(row?.principal_id).toBe("mallory");
    expect(row?.secret_id).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// L3 — createSecret is attributed to its caller
// ---------------------------------------------------------------------------

describe("L3 — create attribution", () => {
  it("attributes the create row to the requesting principal and interface", async () => {
    await engine.createSecret(
      { name: "made-by-agent", type: SecretType.API_KEY, value: new Uint8Array(VALUE) },
      agent("agent-7"),
    );

    const row = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE })[0];
    expect(row?.principal_type).toBe("agent");
    expect(row?.principal_id).toBe("agent-7");
    expect(row?.detail?.interface).toBe("rest");
  });

  it("control: a caller-less create stays NULL-principal (trusted local path)", async () => {
    await engine.createSecret({
      name: "made-locally",
      type: SecretType.API_KEY,
      value: new Uint8Array(VALUE),
    });

    const row = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE })[0];
    expect(row?.principal_id).toBeNull();
    expect(row?.detail?.interface).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// L2 — a downstream child must not outlive the credential
// ---------------------------------------------------------------------------

describe("L2 — downstream teardown on revoke and expiry", () => {
  it("revoking a secret terminates its live downstream child", async () => {
    const id = await makeSecret("mcp-revoke");
    await spawnDownstream("secret://mcp-revoke", "test-mcp");
    expect(terminateRows()).toHaveLength(0);

    await engine.revokeSecret("secret://mcp-revoke");

    expect(terminateRows()).toEqual([{ secretId: id, reason: "secret_revoked" }]);
  });

  it("a use refused because the secret is unusable tears the child down (cross-process case)", async () => {
    await makeSecret("mcp-crossproc");
    await spawnDownstream("secret://mcp-crossproc", "test-mcp");

    // A second process (the CLI) revokes: this engine's registry is untouched,
    // so the child keeps running with the revoked plaintext in its env.
    const other = new VaultEngine({ dbPath, sessionPath: join(tempDir, "other-session.json") });
    await other.unlock("password");
    await other.revokeSecret("secret://mcp-crossproc");
    await other.destroy();

    await expect(
      engine.useSecret("secret://mcp-crossproc", {
        type: "mcp",
        server: "test-mcp",
        tool: "leak",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.SECRET_REVOKED });

    expect(terminateRows().map((r) => r.reason)).toContain("secret_unusable");
  });

  it("lazy expiry terminates the child", async () => {
    const id = await makeSecret("mcp-expiry", undefined, Date.now() + 3_000);
    await spawnDownstream("secret://mcp-expiry", "test-mcp");

    // Expire the secret out of band, then touch it: assertUsable performs the
    // ACTIVE -> EXPIRED transition and the hook must reach the registry.
    const store = new SqliteStore(dbPath);
    store.db.prepare("UPDATE secrets SET expires_at = ? WHERE id = ?").run(Date.now() - 1000, id);
    store.close();

    await expect(engine.getSecretValue("secret://mcp-expiry")).rejects.toMatchObject({
      code: ErrorCode.SECRET_EXPIRED,
    });
    // The teardown is queued off the expiry transaction (D4).
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(terminateRows().map((r) => r.reason)).toContain("secret_expired");
  });

  it("control: an unrelated secret's child survives a revoke", async () => {
    const keptId = await makeSecret("mcp-kept");
    await makeSecret("mcp-other");
    await spawnDownstream("secret://mcp-kept", "kept-mcp");

    await engine.revokeSecret("secret://mcp-other");

    expect(terminateRows()).toHaveLength(0);
    // Still reusable: no respawn row is written on the second use.
    await engine.useSecret("secret://mcp-kept", { type: "mcp", server: "kept-mcp", tool: "leak" });
    expect(
      engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN, secretId: keptId }),
    ).toHaveLength(1);
  });

  it("control: a successful use never terminates the connection", async () => {
    await makeSecret("mcp-happy");
    await spawnDownstream("secret://mcp-happy", "happy-mcp");
    await engine.useSecret("secret://mcp-happy", {
      type: "mcp",
      server: "happy-mcp",
      tool: "leak",
    });
    expect(terminateRows()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// L5 — loadSession enforces the vault-version guard
// ---------------------------------------------------------------------------

describe("L5 — session load honours the vault version", () => {
  it("refuses a vault stamped newer than this binary supports", async () => {
    await engine.destroy();

    const store = new SqliteStore(dbPath);
    store.setMeta("vault_version", "99.0.0");
    store.close();

    const reloaded = new VaultEngine({ dbPath, sessionPath });
    try {
      await expect(reloaded.loadSession()).rejects.toMatchObject({
        code: ErrorCode.VAULT_CORRUPTED,
      });
    } finally {
      await reloaded.destroy();
    }

    // Re-created for the shared afterEach teardown.
    engine = new VaultEngine({ dbPath, sessionPath });
  });

  it("control: a supported version still loads the session", async () => {
    const reloaded = new VaultEngine({ dbPath, sessionPath });
    try {
      expect(await reloaded.loadSession()).toBe(true);
    } finally {
      await reloaded.destroy();
    }
  });
});

// ---------------------------------------------------------------------------
// L10 — audit reads honour the token's project / name-pattern scope
// ---------------------------------------------------------------------------

describe("L10 — audit visibility scope", () => {
  beforeEach(async () => {
    // Rows carrying a secret_id, produced by a path that stamped it long before
    // L4 — so this suite pins the visibility filter alone.
    for (const [name, project] of [
      ["db-prod", undefined],
      ["api-key", undefined],
      ["billing", "finance"],
    ] as [string, string | undefined][]) {
      const id = await makeSecret(name, project);
      registerAgents(`reader-${name}`);
      engine.grantPolicy(
        {
          secretId: id,
          principalType: "agent",
          principalId: `reader-${name}`,
          permissions: ["read"],
        },
        "test-admin",
      );
    }
  });

  it("drops rows about secrets outside the token's name patterns", async () => {
    const dbId = await engine.resolveSecretId("secret://db-prod");
    const apiId = await engine.resolveSecretId("secret://api-key");

    const visible = engine.queryAudit({}, { secrets: ["db-*"] });
    const ids = visible.map((r) => r.secret_id).filter((id): id is string => id !== null);

    expect(ids).toContain(dbId);
    expect(ids).not.toContain(apiId);
  });

  it("answers a targeted secret_id query about a foreign secret with nothing", async () => {
    const apiId = await engine.resolveSecretId("secret://api-key");
    expect(engine.queryAudit({ secretId: apiId }, { secrets: ["db-*"] })).toEqual([]);
    // Control: the same query without the scope does return the rows.
    expect(engine.queryAudit({ secretId: apiId }).length).toBeGreaterThan(0);
  });

  it("drops rows about other projects' secrets", async () => {
    const billingId = await engine.resolveSecretId("secret://finance/billing");
    const dbId = await engine.resolveSecretId("secret://db-prod");

    const visible = engine.queryAudit({}, { project: "finance" });
    const ids = visible.map((r) => r.secret_id).filter((id): id is string => id !== null);

    expect(ids).toContain(billingId);
    expect(ids).not.toContain(dbId);
  });

  it("keeps vault-level rows, which carry no per-secret metadata (D2)", () => {
    const visible = engine.queryAudit({}, { secrets: ["db-*"] });
    expect(visible.some((r) => r.event_type === AuditEventType.VAULT_UNLOCK)).toBe(true);
  });

  it("control: an unscoped read (CLI / unrestricted admin token) sees everything", async () => {
    const apiId = await engine.resolveSecretId("secret://api-key");
    const all = engine.queryAudit();
    expect(all.map((r) => r.secret_id)).toContain(apiId);
    expect(engine.queryAudit({}, undefined).length).toBe(all.length);
  });
});

describe("L5/L10 sanity", () => {
  it("the audit chain stays valid across the attributed and scoped rows", async () => {
    await makeSecret("chain-check");
    await engine.getSecretInfo("secret://chain-check");
    await engine.revokeSecret("secret://chain-check");
    const report = engine.verifyAuditChain();
    expect(report.valid).toBe(true);
  });

  it("VaultError is still the thrown type for the version guard", async () => {
    await engine.destroy();
    const store = new SqliteStore(dbPath);
    store.setMeta("vault_version", "99.0.0");
    store.close();
    const reloaded = new VaultEngine({ dbPath, sessionPath });
    try {
      await reloaded.loadSession();
      expect.fail("should throw");
    } catch (err) {
      expect(err).toBeInstanceOf(VaultError);
    } finally {
      await reloaded.destroy();
    }
    engine = new VaultEngine({ dbPath, sessionPath });
  });
});
