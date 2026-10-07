import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, Permission, PrincipalType, UseSecretAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { McpConnectionEntry } from "./injection/mcp-registry.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents, registryOf } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

/**
 * A downstream MCP child ends when its credential stops being usable: a denied
 * use (E73), a revoke, a lazy expiry or a refusal on an unusable secret (L2).
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
      serverInfo: { name: "mcp-teardown-downstream", version: "1.0.0" },
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
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
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
    protocol: "2025-11-25",
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

const NODE = process.execPath;

const USE: UseSecretAction = {
  type: "process",
  command: NODE,
  args: ["-e", "process.exit(0)"],
  env_var: "SECRET",
};

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
      isolation: { network: false, fs: false },
      strictTreeExit: false,
      spawnedAt: Date.now(),
      lastUsedAt: Date.now(),
    } satisfies McpConnectionEntry),
  );
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
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await expect(engine.getSecretValue("secret://mcp-expiry")).rejects.toMatchObject({
      code: ErrorCode.SECRET_EXPIRED,
    });
    // The teardown is queued off the expiry transaction (D4): its promise is the event.
    expect(terminate).toHaveBeenCalledWith(id, "secret_expired");
    await terminate.mock.results[0]?.value;

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
