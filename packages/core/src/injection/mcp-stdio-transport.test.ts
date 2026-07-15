import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioChildTransport } from "./mcp-stdio-transport.js";

const NODE = process.execPath;

/**
 * Minimal newline-delimited JSON-RPC MCP server: answers initialize (echoing
 * the requested protocol version) and tools/call with an echo tool.
 */
const ECHO_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "echo-test", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      content: [{ type: "text", text: JSON.stringify(m.params.arguments) }],
    }});
  }
});
`;

function makeTransport(script: string): StdioChildTransport {
  return new StdioChildTransport({
    resolvedCommand: NODE,
    args: ["-e", script],
    env: { PATH: process.env.PATH ?? "" },
  });
}

describe("StdioChildTransport — protocol round trip", () => {
  it("connects an SDK client and forwards a tool call", async () => {
    const transport = makeTransport(ECHO_SERVER);
    const client = new Client({ name: "test", version: "0.0.0" });
    await client.connect(transport, { timeout: 5_000 });

    const result = (await client.callTool(
      { name: "echo", arguments: { hello: "world" } },
      undefined,
      { timeout: 5_000 },
    )) as { content: Array<{ type: string; text: string }> };

    expect(result.content[0]?.text).toBe(JSON.stringify({ hello: "world" }));
    await client.close();
  });

  it("exposes the child pid while running", async () => {
    const transport = makeTransport(ECHO_SERVER);
    const client = new Client({ name: "test", version: "0.0.0" });
    await client.connect(transport, { timeout: 5_000 });
    expect(transport.pid).toBeGreaterThan(0);
    await client.close();
  });
});

describe("StdioChildTransport — exit forensics", () => {
  it("records exitInfo BEFORE onclose fires", async () => {
    const transport = makeTransport(`process.exit(7)`);
    let exitAtClose: unknown = "not-set";
    transport.onclose = () => {
      exitAtClose = transport.exitInfo;
    };

    await transport.start();
    await new Promise<void>((resolve) => {
      const prev = transport.onclose;
      transport.onclose = () => {
        prev?.();
        resolve();
      };
    });

    expect(exitAtClose).toEqual({ code: 7, signal: null });
  });

  it("captures stderr into the capped tail without inheriting it", async () => {
    const transport = makeTransport(`process.stderr.write("diagnostic noise"); process.exit(1)`);
    await transport.start();
    await new Promise<void>((resolve) => {
      transport.onclose = () => resolve();
    });
    expect(transport.stderrTail.toString()).toContain("diagnostic noise");
  });
});

describe("StdioChildTransport — teardown", () => {
  it("killSync terminates a long-running child", async () => {
    const transport = makeTransport(`setInterval(() => {}, 1000)`);
    await transport.start();

    const closed = new Promise<void>((resolve) => {
      transport.onclose = () => resolve();
    });
    transport.killSync();
    await closed;

    expect(transport.exitInfo).not.toBeNull();
  });

  it("close() resolves and rejects subsequent sends", async () => {
    const transport = makeTransport(ECHO_SERVER);
    await transport.start();
    await transport.close();

    await expect(transport.send({ jsonrpc: "2.0", id: 1, method: "ping" })).rejects.toThrow(
      "Not connected",
    );
  });

  it("start() rejects when the binary cannot be spawned", async () => {
    const transport = new StdioChildTransport({
      resolvedCommand: "/no/such/binary/xyz123",
      args: [],
      env: {},
    });
    await expect(transport.start()).rejects.toThrow();
  });
});

describe("StdioChildTransport — dead stdin pipe", () => {
  // Regression (macOS CI): a child dying mid-write emitted EPIPE on the stdin
  // stream, which had no 'error' listener — an unhandled 'error' event that
  // crashed the whole test process — and send() could wait forever on a
  // 'drain' that never comes. Destroying the parent-side stream with an EPIPE
  // error reproduces both halves deterministically on every platform: the
  // stream emits 'error' (swallowed by the fix's listener, fatal without it)
  // and the next write must reject through the send() callback.
  it("send() rejects on a dead stdin pipe instead of hanging or crashing", async () => {
    const transport = makeTransport(`setInterval(() => {}, 1000);`);
    await transport.start();

    try {
      const child = (transport as unknown as { child: { stdin: { destroy(e?: Error): void } } })
        .child;
      child.stdin.destroy(new Error("write EPIPE"));
      // Let the destroy's 'error' event fire — unhandled, it would crash here.
      await new Promise((r) => setTimeout(r, 20));

      await expect(transport.send({ jsonrpc: "2.0", id: 1, method: "ping" })).rejects.toThrow();
    } finally {
      transport.killSync();
      await transport.close();
    }
  });
});
