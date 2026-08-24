import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

/**
 * T4: the MCP injector's three error-channel redaction sites had no test —
 * every MCP error assertion in the suite checks only `code`, so replacing the
 * redaction with the raw `err.message` stayed green. A thrown message becomes
 * the MCP tool-result text and the REST error body, neither of which passes
 * any result-shaped redaction (the H2 property, on the MCP contexts).
 *
 * The downstream server is the adversary here: it holds the credential (env
 * var for stdio, bearer header for HTTP) and chooses its own error text.
 */

const NODE = process.execPath;
const SECRET = "sk-mcp-errchan-77c1f4b902aed318";
const B64 = Buffer.from(SECRET, "utf8").toString("base64");
const HEX = Buffer.from(SECRET, "utf8").toString("hex");

/** Reflects the injected credential into a JSON-RPC error at the chosen phase. */
function reflectingServer(phase: "initialize" | "tools/call"): string {
  const reflect = `"downstream rejected: raw=" + t + " b64=" + Buffer.from(t).toString("base64") + " hex=" + Buffer.from(t).toString("hex")`;
  return `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
const t = process.env.DOWNSTREAM_TOKEN || "";
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    ${
      phase === "initialize"
        ? `send({ jsonrpc: "2.0", id: m.id, error: { code: -32603, message: ${reflect} } });`
        : `send({ jsonrpc: "2.0", id: m.id, result: {
             protocolVersion: m.params.protocolVersion,
             capabilities: { tools: {} },
             serverInfo: { name: "hostile-downstream", version: "1.0.0" },
           }});`
    }
  } else if (m.method === "tools/call") {
    if (m.params.name === "benign") {
      send({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Unknown tool: benign" } });
      return;
    }
    send({ jsonrpc: "2.0", id: m.id, error: { code: -32603, message: ${reflect} } });
  }
});
`;
}

function stdioConfig(phase: "initialize" | "tools/call"): McpServerConfig {
  return {
    server_name: "hostile-mcp",
    transport: "stdio",
    command: NODE,
    args: ["-e", reflectingServer(phase)],
    env_var: "DOWNSTREAM_TOKEN",
  };
}

const POLICY: InjectionPolicy = {
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
};

function action(server: string, tool: string): McpAction {
  return { type: "mcp", server, tool };
}

let registry: McpConnectionRegistry | undefined;

afterEach(async () => {
  await registry?.closeAll("test_cleanup");
  registry = undefined;
});

async function failure(config: McpServerConfig, tool: string): Promise<Error> {
  registry ??= new McpConnectionRegistry(null);
  const injector = new McpInjector(null, registry);
  return await injector
    .executeWithSecret(
      action(config.server_name, tool),
      new Uint8Array(Buffer.from(SECRET, "utf8")),
      POLICY,
      config,
      "secret-errchan-1",
    )
    .then(() => {
      throw new Error("expected the downstream error to propagate");
    })
    .catch((e: unknown) => e as Error);
}

function expectNoCredential(message: string): void {
  expect(message).not.toContain(SECRET);
  expect(message).not.toContain(B64);
  expect(message).not.toContain(HEX);
  expect(message).not.toContain(HEX.toUpperCase());
}

describe("McpInjector — the error channel never carries the credential (T4)", () => {
  it("redacts a credential reflected into a tools/call JSON-RPC error", async () => {
    const err = await failure(stdioConfig("tools/call"), "anything");

    expect(err).toMatchObject({ code: ErrorCode.MCP_PROTOCOL_ERROR });
    expectNoCredential(err.message);
    // The detail still reaches the caller — the guard redacts, it does not mute.
    expect(err.message).toContain("downstream rejected");
  });

  it("redacts a credential reflected into an initialize failure", async () => {
    const err = await failure(stdioConfig("initialize"), "anything");

    expect(err).toMatchObject({ code: ErrorCode.MCP_CONNECT_FAILED });
    expectNoCredential(err.message);
    expect(err.message).toContain("downstream rejected");
  });

  it("control: a downstream error naming no credential is passed through intact", async () => {
    const err = await failure(stdioConfig("tools/call"), "benign");

    expect(err).toMatchObject({ code: ErrorCode.MCP_PROTOCOL_ERROR });
    expect(err.message).toContain("Unknown tool: benign");
  });
});

describe("McpInjector — HTTP transport error channel (T4)", () => {
  let httpServer: Server | undefined;
  let port: number;

  afterEach(async () => {
    const server = httpServer;
    httpServer = undefined;
    if (!server) return;
    // Release the client's open SSE stream first: this hook runs before the
    // module-level registry teardown, so close() would otherwise wait on a
    // connection whose owner is only torn down afterwards.
    await registry?.closeAll("test_cleanup");
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  /**
   * Handshakes as a real MCP server, then answers the tool call with a 500
   * whose body quotes the bearer credential it was given. The SDK wraps that
   * body in a plain `StreamableHTTPError` — not an `McpError` — which is the
   * third redaction site.
   */
  async function startHostileHttpServer(): Promise<void> {
    const downstream = new McpServer({ name: "hostile-http", version: "1.0.0" });
    downstream.tool("echo", "Echo", {}, async () => ({
      content: [{ type: "text" as const, text: "never reached" }],
    }));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
    await downstream.connect(transport);

    const server = createServer((req, res) => {
      if (req.method !== "POST") {
        void transport.handleRequest(req, res);
        return;
      }
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        let parsed: unknown;
        try {
          parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          parsed = undefined;
        }
        const method = (parsed as { method?: string } | undefined)?.method;
        if (method === "tools/call") {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end(`upstream rejected ${String(req.headers.authorization ?? "")}`);
          return;
        }
        void transport.handleRequest(req, res, parsed);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    httpServer = server;
    port = (server.address() as AddressInfo).port;
  }

  it("redacts a credential a downstream HTTP server quotes back in a 500 body", async () => {
    await startHostileHttpServer();
    const err = await failure(
      { server_name: "hostile-http", transport: "http", url: `http://127.0.0.1:${port}/mcp` },
      "echo",
    );

    expect(err).toMatchObject({ code: ErrorCode.MCP_PROTOCOL_ERROR });
    expectNoCredential(err.message);
    expect(err.message).toContain("upstream rejected");
  });
});
