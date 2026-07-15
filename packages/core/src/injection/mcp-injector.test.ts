import { afterEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

const NODE = process.execPath;
const SECRET = "sk-mcp-supersecret-abcdef123456";

/**
 * Inline downstream MCP server (newline-delimited JSON-RPC over stdio) with
 * tools exercising the lifecycle and leakage surfaces: echo, leak-env,
 * leak-structured, error-tool, crash (exits mid-call), slow.
 */
const TEST_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "harpoc-test-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    const name = m.params.name;
    const args = m.params.arguments || {};
    if (name === "crash") { process.exit(7); }
    if (name === "slow") { return; }
    if (name === "echo") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: JSON.stringify(args) }],
      }});
    } else if (name === "pid") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: String(process.pid) }],
      }});
    } else if (name === "leak-env") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: process.env.DOWNSTREAM_TOKEN || "unset" }],
      }});
    } else if (name === "leak-env-b64") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: Buffer.from(process.env.DOWNSTREAM_TOKEN || "").toString("base64") }],
      }});
    } else if (name === "leak-structured") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [],
        structuredContent: { nested: { secret: process.env.DOWNSTREAM_TOKEN || "unset" } },
      }});
    } else if (name === "error-tool") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: "tool failed" }], isError: true,
      }});
    } else if (name === "big") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: "A".repeat(1200000) }],
      }});
    } else {
      send({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Unknown tool: " + name } });
    }
  }
});
`;

const STDIO_CONFIG: McpServerConfig = {
  server_name: "test-mcp",
  transport: "stdio",
  command: NODE,
  args: ["-e", TEST_SERVER],
  env_var: "DOWNSTREAM_TOKEN",
};

const POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [NODE],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
};

function mcpAction(tool: string, overrides: Partial<McpAction> = {}): McpAction {
  return {
    type: "mcp",
    server: "test-mcp",
    tool,
    ...overrides,
  };
}

let registry: McpConnectionRegistry;
let injector: McpInjector;

function freshInjector(): void {
  registry = new McpConnectionRegistry(null);
  injector = new McpInjector(null, registry);
}
freshInjector();

function run(
  action: McpAction,
  {
    config = STDIO_CONFIG,
    policy = POLICY,
    secret = SECRET,
    secretId = "secret-1",
  }: {
    config?: McpServerConfig;
    policy?: InjectionPolicy;
    secret?: string;
    secretId?: string;
  } = {},
) {
  return injector.executeWithSecret(
    action,
    new Uint8Array(Buffer.from(secret, "utf8")),
    policy,
    config,
    secretId,
  );
}

afterEach(async () => {
  await registry.closeAll("test_cleanup");
  freshInjector();
});

describe("McpInjector — validation", () => {
  it("rejects a server name that does not match the configured one", async () => {
    await expect(run(mcpAction("echo", { server: "other-mcp" }))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_MISMATCH,
    });
  });

  it("fail-safe denies stdio launch when the command allowlist is empty", async () => {
    await expect(
      run(mcpAction("echo"), { policy: { ...POLICY, command_allowlist: [] } }),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });

  it("denies an http endpoint not on the URL allowlist", async () => {
    await expect(
      run(mcpAction("echo"), {
        config: { server_name: "test-mcp", transport: "http", url: "https://evil.example.com/mcp" },
        policy: { ...POLICY, url_allowlist: ["https://good.example.com/*"] },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
  });

  it("rejects a plaintext http endpoint on a non-loopback host", async () => {
    await expect(
      run(mcpAction("echo"), {
        config: { server_name: "test-mcp", transport: "http", url: "http://api.example.com/mcp" },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.URL_HTTPS_REQUIRED });
  });
});

describe("McpInjector — tool call forwarding", () => {
  it("forwards a tool call and returns the sanitized result", async () => {
    const result = await run(mcpAction("echo", { arguments: { visibility: "public" } }));
    expect(result.type).toBe("mcp");
    expect(result.content).toEqual([
      { type: "text", text: JSON.stringify({ visibility: "public" }) },
    ]);
    expect(result.is_error).toBeUndefined();
  });

  it("passes a downstream tool-level error through in-band", async () => {
    const result = await run(mcpAction("error-tool"));
    expect(result.is_error).toBe(true);
  });

  it("maps a downstream protocol error to MCP_PROTOCOL_ERROR", async () => {
    await expect(run(mcpAction("no-such-tool"))).rejects.toMatchObject({
      code: ErrorCode.MCP_PROTOCOL_ERROR,
    });
  });

  it("times out a slow tool without killing the server", async () => {
    await expect(run(mcpAction("slow", { timeout_ms: 300 }))).rejects.toMatchObject({
      code: ErrorCode.MCP_TIMEOUT,
    });
    // Server survives: the same connection answers the next call.
    expect(registry.get("secret-1")).toBeDefined();
    const result = await run(mcpAction("echo", { arguments: { after: "timeout" } }));
    expect(result.content).toEqual([{ type: "text", text: JSON.stringify({ after: "timeout" }) }]);
  });
});

describe("McpInjector — output sanitization (I2b)", () => {
  it("redacts the credential echoed from the downstream env", async () => {
    const result = await run(mcpAction("leak-env"));
    const text = JSON.stringify(result);
    expect(text).not.toContain(SECRET);
    expect(text).toContain("[REDACTED]");
  });

  it("redacts a base64 encoding of the credential", async () => {
    const result = await run(mcpAction("leak-env-b64"));
    const text = JSON.stringify(result);
    expect(text).not.toContain(Buffer.from(SECRET, "utf8").toString("base64"));
    expect(text).toContain("[REDACTED]");
  });

  it("redacts the credential inside structured_content leaves", async () => {
    const result = await run(mcpAction("leak-structured"));
    expect(result.structured_content).toEqual({ nested: { secret: "[REDACTED]" } });
  });

  it("caps an oversized result and flags truncation", async () => {
    const result = await run(mcpAction("big"));
    expect(result.truncated).toBe(true);
    expect(JSON.stringify(result).length).toBeLessThan(1_100_000);
  });
});

describe("McpInjector — lifecycle (thesis §4.5.4)", () => {
  it("spawns on first use and reuses the server across calls", async () => {
    const first = await run(mcpAction("pid"));
    const second = await run(mcpAction("pid"));
    expect(first.content).toEqual(second.content);
  });

  it("a crash mid-call fails visibly with exit forensics and removes the entry", async () => {
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBeDefined();

    await expect(run(mcpAction("crash"))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_CRASHED,
      details: { server: "test-mcp", exit_code: 7, signal: null },
    });

    // Removed on crash — no auto-respawn.
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("respawns on the next invocation after a crash", async () => {
    const before = await run(mcpAction("pid"));
    await expect(run(mcpAction("crash"))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_CRASHED,
    });

    const after = await run(mcpAction("pid"));
    expect(after.content).not.toEqual(before.content);
  });

  it("coalesces concurrent first calls onto a single spawn", async () => {
    const [a, b] = await Promise.all([run(mcpAction("pid")), run(mcpAction("pid"))]);
    expect(a.content).toEqual(b.content);
  });

  it("terminates and respawns when the credential rotates", async () => {
    const before = await run(mcpAction("pid"));
    const after = await run(mcpAction("pid"), { secret: "sk-rotated-value-999999" });
    expect(after.content).not.toEqual(before.content);
  });

  it("terminates and respawns when the config changes", async () => {
    const before = await run(mcpAction("pid"));
    const changed: McpServerConfig = { ...STDIO_CONFIG, working_directory: process.cwd() };
    const after = await run(mcpAction("pid"), { config: changed });
    expect(after.content).not.toEqual(before.content);
  });

  it("closeAll terminates live servers", async () => {
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBeDefined();
    await registry.closeAll("session_end");
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("killAllSync clears the registry without awaiting", async () => {
    await run(mcpAction("echo"));
    registry.killAllSync();
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("a spawn failure surfaces as MCP_CONNECT_FAILED and retries fresh", async () => {
    const dying: McpServerConfig = { ...STDIO_CONFIG, args: ["-e", "process.exit(1)"] };
    await expect(run(mcpAction("echo"), { config: dying })).rejects.toMatchObject({
      code: ErrorCode.MCP_CONNECT_FAILED,
    });
    // The failed connect did not poison the registry: a good config works.
    const result = await run(mcpAction("echo"));
    expect(result.type).toBe("mcp");
  });
});

describe("McpInjector — network isolation (§4.5.3 layer 4)", () => {
  it("refuses a stdio downstream fail-closed before any acquire", async () => {
    const acquireSpy = vi.spyOn(registry, "acquire");
    await expect(
      run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } }),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(acquireSpy).not.toHaveBeenCalled();
  });

  it("terminates a live un-isolated child before refusing (policy tightened elsewhere)", async () => {
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBeDefined();
    await expect(
      run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } }),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("leaves the live child alone when the policy does not demand isolation", async () => {
    await run(mcpAction("echo"));
    const entry = registry.get("secret-1");
    expect(entry).toBeDefined();
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBe(entry);
  });

  it("audits the stdio refusal with the error code", async () => {
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    await expect(
      auditedInjector.executeWithSecret(
        mcpAction("echo"),
        new Uint8Array(Buffer.from(SECRET, "utf8")),
        { ...POLICY, network_isolation: true },
        STDIO_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
  });

  it("does not gate an HTTP downstream on the flag (request-mediated, no child)", async () => {
    // The connect itself fails (nothing listens on the port) — the point is
    // that the failure is NOT the isolation refusal: the D1/D2 boundary.
    const err = await run(mcpAction("echo"), {
      config: { server_name: "test-mcp", transport: "http", url: "http://127.0.0.1:9/mcp" },
      policy: { ...POLICY, network_isolation: true },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VaultError);
    expect((err as VaultError).code).not.toBe(ErrorCode.NETWORK_ISOLATION_UNAVAILABLE);
  });
});
