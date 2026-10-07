import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import type { vi } from "vitest";
import type { IsolationDimensions, IsolationWrap } from "../isolation.js";

export const NODE = process.execPath;
export const SECRET = "sk-mcp-supersecret-abcdef123456";

/**
 * Inline downstream MCP server (newline-delimited JSON-RPC over stdio) with
 * tools exercising the lifecycle and leakage surfaces: echo, leak-env,
 * leak-structured, env-keys, error-tool, crash (exits mid-call), slow.
 */
export const TEST_SERVER = `
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
    } else if (name === "env-keys") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: JSON.stringify(Object.keys(process.env).sort()) }],
      }});
    } else if (name === "error-tool") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: "tool failed" }], isError: true,
      }});
    } else if (name === "big") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: "A".repeat(1200000) }],
      }});
    } else if (name === "big-structured") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [{ type: "text", text: "keep-1" }, { type: "text", text: "keep-2" }],
        structuredContent: { blob: "A".repeat(1200000) },
      }});
    } else if (name === "big-tail") {
      send({ jsonrpc: "2.0", id: m.id, result: {
        content: [
          { type: "text", text: "lead" },
          { type: "text", text: "A".repeat(1200000) },
          { type: "text", text: "tail" },
        ],
      }});
    } else {
      send({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Unknown tool: " + name } });
    }
  }
});
`;

export const STDIO_CONFIG: McpServerConfig = {
  server_name: "test-mcp",
  transport: "stdio",
  protocol: "2025-11-25",
  command: NODE,
  args: ["-e", TEST_SERVER],
  env_var: "DOWNSTREAM_TOKEN",
};

/**
 * A node-scripted stand-in for the platform wrapper. Like bwrap it stays as a
 * monitor, hands its pipes to the payload and returns the payload's exit
 * status — so the wrapped spawn runs end to end on every platform, the win32
 * host included, without a kernel feature. The mechanism tags it reports are
 * whatever the demanded dimensions would carry on a Linux primary.
 */
export const MONITOR_WRAPPER = `
const [command, ...args] = process.argv.slice(1);
const child = require("node:child_process").spawn(command, args, { stdio: "inherit" });
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
`;

export function monitorWrap(
  command: string,
  args: readonly string[],
  dims: IsolationDimensions,
): Promise<IsolationWrap> {
  return Promise.resolve({
    command: NODE,
    args: ["-e", MONITOR_WRAPPER, command, ...args],
    ...(dims.network ? { networkMechanism: "unshare" as const } : {}),
    ...(dims.fs ? { fsMechanism: "landlock" as const } : {}),
  });
}

export function secretBytes(): Uint8Array {
  return new Uint8Array(Buffer.from(SECRET, "utf8"));
}

export type LoggedRow = { eventType: string; success: boolean; detail: Record<string, unknown> };

export function spawnRowOf(log: ReturnType<typeof vi.fn>): LoggedRow | undefined {
  return log.mock.calls.map((c) => c[0] as LoggedRow).find((r) => r.eventType === "mcp.spawn");
}

export function payloadPidOf(result: unknown): number {
  const digits = JSON.stringify((result as { content?: unknown }).content).match(/\d+/);
  return Number(digits?.[0] ?? "0");
}

export const POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [NODE],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
  strict_tree_exit: false,
};

export function mcpAction(tool: string, overrides: Partial<McpAction> = {}): McpAction {
  return {
    type: "mcp",
    server: "test-mcp",
    tool,
    ...overrides,
  };
}
