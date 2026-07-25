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

/**
 * M5. Downstream stdout was buffered with no size cap (stderr has one, results
 * have one), and the drain loop `continue`d on a readMessage failure — so a
 * failure thrown BEFORE the buffer advanced (a line too large to even
 * stringify) spun a synchronous loop inside the 'data' handler and blocked the
 * vault's event loop permanently. A single malformed or oversized line from a
 * downstream server — hostile, or merely buggy — was enough.
 */
describe("StdioChildTransport — untrusted downstream stdout framing", () => {
  /** Wait for a condition rather than a fixed delay — CI load is not bounded. */
  const settle = async (until: () => boolean, timeoutMs = 5_000): Promise<void> => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline && !until()) {
      await new Promise((r) => setTimeout(r, 20));
    }
  };

  it("keeps the event loop responsive while a huge unframed line streams in", async () => {
    // 6 MiB with no newline: past the 4 MiB cap, so the connection must fail
    // rather than buffer the stream in the vault's memory.
    const transport = makeTransport(
      `process.stdout.write("x".repeat(6 * 1024 * 1024)); setInterval(() => {}, 1000);`,
    );
    const errors: Error[] = [];
    transport.onerror = (err) => errors.push(err);
    const closed = new Promise<void>((resolve) => {
      transport.onclose = () => resolve();
    });

    await transport.start();

    // A timer that must still fire proves the event loop was never blocked.
    let ticked = false;
    const ticker = setTimeout(() => {
      ticked = true;
    }, 10);
    await closed;
    clearTimeout(ticker);

    expect(ticked).toBe(true);
    expect(errors.some((e) => /unframed stdout/.test(e.message))).toBe(true);
    expect(transport.exitInfo).not.toBeNull();
  }, 20_000);

  it("a malformed line is reported and the stream keeps working", async () => {
    const transport = makeTransport(
      `process.stdout.write("not json at all\\n");
       process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }) + "\\n");
       setInterval(() => {}, 1000);`,
    );
    const errors: Error[] = [];
    const messages: unknown[] = [];
    transport.onerror = (err) => errors.push(err);
    transport.onmessage = (msg) => messages.push(msg);

    await transport.start();
    await settle(() => errors.length > 0 && messages.length > 0);

    try {
      expect(errors.length).toBe(1);
      // The good line after the bad one still arrives — the drain loop advanced
      // past the malformed line instead of retrying it forever.
      expect(messages).toEqual([{ jsonrpc: "2.0", id: 1, result: {} }]);
    } finally {
      transport.killSync();
      await transport.close();
    }
  }, 20_000);

  it("a parse failure cannot spin the drain loop: the line is consumed first", async () => {
    const transport = makeTransport(`setInterval(() => {}, 1000);`);
    await transport.start();

    try {
      const internals = transport as unknown as {
        deserializeMessage: (line: string) => unknown;
        stdoutBuffer: Buffer;
        onStdout(chunk: Buffer): void;
      };
      // A parser that throws on every line stands in for the case that made the
      // old loop non-terminating: a line so large it cannot even be stringified
      // threw BEFORE the buffer had advanced, and the `continue` retried it
      // forever. If the fix regresses, this call never returns — the drain runs
      // synchronously inside the 'data' handler, so no test timeout can fire.
      internals.deserializeMessage = () => {
        throw new Error("cannot parse");
      };
      const errors: Error[] = [];
      transport.onerror = (err) => errors.push(err);

      internals.onStdout(Buffer.from("one\ntwo\nthree\n"));

      expect(internals.stdoutBuffer.length).toBe(0);
      expect(errors.length).toBe(3);
    } finally {
      transport.killSync();
      await transport.close();
    }
  }, 20_000);

  it("control: messages split across chunk boundaries still reassemble", async () => {
    const transport = makeTransport(
      `const msg = JSON.stringify({ jsonrpc: "2.0", id: 42, result: { ok: true } }) + "\\n";
       let i = 0;
       const t = setInterval(() => {
         process.stdout.write(msg[i]);
         if (++i === msg.length) clearInterval(t);
       }, 1);
       setInterval(() => {}, 1000);`,
    );
    const messages: unknown[] = [];
    transport.onmessage = (msg) => messages.push(msg);

    await transport.start();
    await settle(() => messages.length > 0);

    try {
      expect(messages).toEqual([{ jsonrpc: "2.0", id: 42, result: { ok: true } }]);
    } finally {
      transport.killSync();
      await transport.close();
    }
  }, 20_000);

  it("control: a line just under the cap is still delivered", async () => {
    const transport = makeTransport(
      `const pad = "y".repeat(1024 * 1024);
       process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: 9, result: { pad } }) + "\\n");
       setInterval(() => {}, 1000);`,
    );
    const messages: { id?: number }[] = [];
    transport.onmessage = (msg) => messages.push(msg as { id?: number });

    await transport.start();
    await settle(() => messages.length > 0);

    try {
      expect(messages.map((m) => m.id)).toEqual([9]);
    } finally {
      transport.killSync();
      await transport.close();
    }
  }, 20_000);
});
