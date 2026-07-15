import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * MCP proxy context (thesis §4.5.4).
 *
 * End-to-end exercise of the vault as a transparent MCP proxy: stdio transport
 * (process-mediated — downstream server spawned with the credential in a clean
 * env) and Streamable HTTP transport (request-mediated — bearer injection).
 * The lifecycle assertions pin the §4.5.4 discipline: spawn on first use,
 * reuse across calls, crash fails visibly and is audit-logged, respawn only on
 * the next invocation, terminate on session end.
 */

const PASSWORD = "integration-test-pw";
const SECRET = "sk-mcp-secret-1a2b3c4d5e6f";
const NODE = process.execPath;

const DOWNSTREAM_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "integ-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    const name = m.params.name;
    if (name === "crash") { process.exit(7); }
    if (name === "echo") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: JSON.stringify(m.params.arguments || {}) }],
      }});
    } else if (name === "pid") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: String(process.pid) }],
      }});
    } else if (name === "leak-env") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: process.env.TOKEN || "unset" }],
      }});
    } else if (name === "leak-structured") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [],
        structuredContent: { secret: process.env.TOKEN || "unset" },
      }});
    } else if (name === "transform") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: [...(process.env.TOKEN || "")].reverse().join("") }],
      }});
    } else {
      send({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Unknown tool" } });
    }
  }
});
`;

function mcpAction(tool: string, args?: Record<string, unknown>) {
  return { type: "mcp" as const, server: "integ-mcp", tool, arguments: args };
}

describe("MCP proxy context — stdio transport (thesis §4.5.4)", () => {
  let vault: TestVault;
  let handle: string;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "mcp-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    handle = created.handle;
    // NODE is a known interpreter (§4.5.3) — the common case for stdio MCP
    // servers, so the launch command needs the explicit acknowledgement.
    await vault.engine.setInjectionPolicy(
      handle,
      { url_allowlist: [], command_allowlist: [NODE], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await vault.engine.setMcpServerConfig(handle, {
      server_name: "integ-mcp",
      transport: "stdio",
      command: NODE,
      args: ["-e", DOWNSTREAM_SERVER],
      env_var: "TOKEN",
    });
  });

  afterEach(async () => {
    await destroyTestVault(vault);
  });

  it("forwards a tool call end-to-end (multi-interface: DirectClient)", async () => {
    const client = new DirectClient(vault.engine);
    const res = await client.useSecret(handle, mcpAction("echo", { visibility: "public" }));
    if (res.type !== "mcp") throw new Error("expected mcp result");
    expect(res.content).toEqual([{ type: "text", text: JSON.stringify({ visibility: "public" }) }]);
  });

  it("I1: the credential never appears in the value returned to the caller", async () => {
    const res = await vault.engine.useSecret(handle, mcpAction("echo", { ok: true }));
    expect(JSON.stringify(res)).not.toContain(SECRET);
  });

  // --- Lifecycle: spawn on first use, reuse, crash, no auto-respawn ----------

  it("spawns on first use and reuses across calls (single mcp.spawn audit)", async () => {
    await vault.engine.useSecret(handle, mcpAction("echo"));
    await vault.engine.useSecret(handle, mcpAction("echo"));

    const spawns = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    expect(spawns).toHaveLength(1);
    expect(spawns[0]?.detail?.server).toBe("integ-mcp");
    expect(spawns[0]?.detail?.transport).toBe("stdio");
  });

  it("a crash fails visibly, is audit-logged, and does NOT auto-respawn", async () => {
    await vault.engine.useSecret(handle, mcpAction("echo"));

    await expect(vault.engine.useSecret(handle, mcpAction("crash"))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_CRASHED,
      details: { server: "integ-mcp", exit_code: 7, signal: null },
    });

    // Crash recorded with exit forensics.
    const crashes = vault.engine.queryAudit({ eventType: AuditEventType.MCP_CRASH });
    expect(crashes).toHaveLength(1);
    expect(crashes[0]?.detail?.exit_code).toBe(7);
    expect(crashes[0]?.success).toBe(false);

    // No auto-respawn: still exactly one spawn event after the crash.
    expect(vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN })).toHaveLength(1);
  });

  it("respawns on the NEXT invocation after a crash, re-injecting the credential", async () => {
    const before = await vault.engine.useSecret(handle, mcpAction("pid"));
    await expect(vault.engine.useSecret(handle, mcpAction("crash"))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_CRASHED,
    });

    const after = await vault.engine.useSecret(handle, mcpAction("pid"));
    expect(after.type).toBe("mcp");
    expect(after).not.toEqual(before);

    // The respawn is invocation-driven: a second spawn event exists now.
    expect(vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN })).toHaveLength(2);

    // Credential re-injected into the fresh environment (redacted on echo).
    const leak = await vault.engine.useSecret(handle, mcpAction("leak-env"));
    expect(JSON.stringify(leak)).toContain("[REDACTED]");
  });

  it("lock() terminates the downstream child (mcp.terminate audited)", async () => {
    await vault.engine.useSecret(handle, mcpAction("echo"));
    const spawns = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    const pid = spawns[0]?.detail?.pid as number;
    expect(pid).toBeGreaterThan(0);

    await vault.engine.lock();

    // The child must be gone after session end.
    await expect
      .poll(
        () => {
          try {
            process.kill(pid, 0);
            return "alive";
          } catch {
            return "dead";
          }
        },
        { timeout: 5_000 },
      )
      .toBe("dead");

    await vault.engine.unlock(PASSWORD);
    const terminates = vault.engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("vault_lock");
  });

  it("enabling network_isolation terminates the live un-isolated child (mcp.terminate audited)", async () => {
    await vault.engine.useSecret(handle, mcpAction("echo"));
    const spawns = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    const pid = spawns[0]?.detail?.pid as number;
    expect(pid).toBeGreaterThan(0);

    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [NODE],
      env_allowlist: [],
      network_isolation: true,
    });

    // The credential-holding child must not survive the isolation demand.
    await expect
      .poll(
        () => {
          try {
            process.kill(pid, 0);
            return "alive";
          } catch {
            return "dead";
          }
        },
        { timeout: 5_000 },
      )
      .toBe("dead");

    const terminates = vault.engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("network_isolation_enabled");

    // Fail-closed follow-through: the next invocation is refused outright.
    await expect(vault.engine.useSecret(handle, mcpAction("echo"))).rejects.toMatchObject({
      code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
    });
  });

  it("control: re-asserting the policy without the flag leaves the child alive", async () => {
    await vault.engine.useSecret(handle, mcpAction("echo"));
    const pid = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN })[0]?.detail
      ?.pid as number;
    expect(pid).toBeGreaterThan(0);

    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [NODE],
      env_allowlist: [],
    });

    expect(vault.engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE })).toHaveLength(0);
    // Reused, not respawned: still a single spawn event after another call.
    await vault.engine.useSecret(handle, mcpAction("echo"));
    expect(vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN })).toHaveLength(1);
    process.kill(pid, 0);
  });

  it("rotation terminates the stale child and respawns with the new credential", async () => {
    await vault.engine.useSecret(handle, mcpAction("echo"));
    await vault.engine.rotateSecret(handle, new Uint8Array(Buffer.from("sk-rotated-000111")));

    const res = await vault.engine.useSecret(handle, mcpAction("leak-env"));
    const text = JSON.stringify(res);
    // The fresh child carries the NEW value (redacted); the old one never echoes.
    expect(text).toContain("[REDACTED]");
    expect(text).not.toContain("sk-rotated-000111");

    expect(vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN })).toHaveLength(2);
    const terminates = vault.engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates.some((e) => e.detail?.reason === "credential_rotated")).toBe(true);
  });

  // --- Output sanitization parity with the process context (I2b) -------------

  it("blocked: a naive credential echo through the downstream tool is redacted", async () => {
    const res = await vault.engine.useSecret(handle, mcpAction("leak-env"));
    const text = JSON.stringify(res);
    expect(text).not.toContain(SECRET);
    expect(text).toContain("[REDACTED]");
  });

  it("blocked: a credential inside structured_content is redacted", async () => {
    const res = await vault.engine.useSecret(handle, mcpAction("leak-structured"));
    if (res.type !== "mcp") throw new Error("expected mcp result");
    expect(res.structured_content).toEqual({ secret: "[REDACTED]" });
  });

  it("L3 residual: an arbitrary transform passes through (documented, parity with process context)", async () => {
    const res = await vault.engine.useSecret(handle, mcpAction("transform"));
    expect(JSON.stringify(res)).toContain([...SECRET].reverse().join(""));
  });

  // --- Target allowlisting ----------------------------------------------------

  it("fail-safe: stdio launch is denied without a command allowlist", async () => {
    const created = await vault.engine.createSecret({
      name: "no-allow",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    await vault.engine.setMcpServerConfig(created.handle, {
      server_name: "integ-mcp",
      transport: "stdio",
      command: NODE,
      args: ["-e", DOWNSTREAM_SERVER],
      env_var: "TOKEN",
    });
    await expect(vault.engine.useSecret(created.handle, mcpAction("echo"))).rejects.toMatchObject({
      code: ErrorCode.COMMAND_NOT_ALLOWED,
    });
  });

  it("rejects an action naming a server other than the configured one", async () => {
    await expect(
      vault.engine.useSecret(handle, { type: "mcp", server: "other-mcp", tool: "echo" }),
    ).rejects.toMatchObject({ code: ErrorCode.MCP_SERVER_MISMATCH });
  });

  it("rejects an mcp action for a secret with no server config", async () => {
    const created = await vault.engine.createSecret({
      name: "no-config",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    await expect(vault.engine.useSecret(created.handle, mcpAction("echo"))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_NOT_CONFIGURED,
    });
  });
});

describe("MCP proxy context — Streamable HTTP transport (request-mediated)", () => {
  let vault: TestVault;
  let handle: string;
  let httpServer: Server;
  let baseUrl: string;
  let receivedAuthHeaders: string[];

  beforeEach(async () => {
    receivedAuthHeaders = [];

    // Downstream MCP server over Streamable HTTP on loopback.
    const downstream = new McpServer({ name: "integ-http-downstream", version: "1.0.0" });
    downstream.tool("whoami", "Echo the received Authorization header", {}, async () => ({
      content: [{ type: "text" as const, text: receivedAuthHeaders.at(-1) ?? "none" }],
    }));
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });
    await downstream.connect(transport);

    httpServer = createServer((req, res) => {
      receivedAuthHeaders.push(String(req.headers.authorization ?? "none"));
      void transport.handleRequest(req, res);
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    const addr = httpServer.address() as { port: number };
    baseUrl = `http://127.0.0.1:${addr.port}/mcp`;

    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "mcp-http-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(SECRET, "utf8")),
    });
    handle = created.handle;
    await vault.engine.setMcpServerConfig(handle, {
      server_name: "integ-mcp",
      transport: "http",
      url: baseUrl,
    });
  });

  afterEach(async () => {
    await destroyTestVault(vault);
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  it("injects the bearer credential downstream and never returns it to the caller", async () => {
    const res = await vault.engine.useSecret(handle, mcpAction("whoami"));
    if (res.type !== "mcp") throw new Error("expected mcp result");

    // The downstream server actually received the credential...
    expect(receivedAuthHeaders).toContain(`Bearer ${SECRET}`);

    // ...but the caller-visible result (which echoes the auth header) is redacted.
    const text = JSON.stringify(res);
    expect(text).not.toContain(SECRET);
    expect(text).toContain("[REDACTED]");
  });

  it("audits the HTTP connect as mcp.spawn with the endpoint URL", async () => {
    await vault.engine.useSecret(handle, mcpAction("whoami"));
    const spawns = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    expect(spawns).toHaveLength(1);
    expect(spawns[0]?.detail?.transport).toBe("http");
    expect(spawns[0]?.detail?.url).toBe(baseUrl);
  });

  it("URL allowlisting blocks a non-allowlisted downstream endpoint", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: ["https://api.github.com/*"],
      command_allowlist: [],
      env_allowlist: [],
    });
    await expect(vault.engine.useSecret(handle, mcpAction("whoami"))).rejects.toMatchObject({
      code: ErrorCode.URL_NOT_ALLOWED,
    });
  });
});
