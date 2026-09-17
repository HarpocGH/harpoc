import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/server";
import {
  CLIENT_CAPABILITIES_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import type { VaultEngine } from "@harpoc/core";
import { createStdioServerFactory } from "./server.js";

function makeEngine(): VaultEngine {
  return {
    auditServerStart: vi.fn(),
    isTokenRevoked: vi.fn().mockReturnValue(false),
    getState: vi.fn().mockReturnValue("unlocked"),
  } as unknown as VaultEngine;
}

/** One JSON-RPC line in, the matching response out. */
function pipe(): {
  transport: StdioServerTransport;
  send(message: Record<string, unknown>): void;
  receive(id: number): Promise<Record<string, unknown>>;
} {
  const input = new PassThrough();
  const output = new PassThrough();
  const lines: string[] = [];
  const waiters: Array<() => void> = [];
  let buffer = "";
  output.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf8");
    let at: number;
    while ((at = buffer.indexOf("\n")) >= 0) {
      lines.push(buffer.slice(0, at));
      buffer = buffer.slice(at + 1);
    }
    for (const wake of waiters.splice(0)) wake();
  });
  return {
    transport: new StdioServerTransport(input, output),
    send: (message) => input.write(`${JSON.stringify(message)}\n`),
    receive: async (id) => {
      for (;;) {
        const hit = lines
          .map((line) => JSON.parse(line) as Record<string, unknown>)
          .find((message) => message.id === id);
        if (hit) return hit;
        await new Promise<void>((resolve) => waiters.push(resolve));
      }
    },
  };
}

describe("createStdioServerFactory over one stdio pipe (P3-24)", () => {
  it("a discover then a claim-less initialize land on two distinct instances, one server.start row", async () => {
    const engine = makeEngine();
    const inner = createStdioServerFactory({ engine, allowTokenless: true });
    const built: McpServer[] = [];
    const factory = () => {
      const server = inner();
      built.push(server);
      return server;
    };
    const { transport, send, receive } = pipe();
    const handle = serveStdio(factory, { transport });
    try {
      send({
        jsonrpc: "2.0",
        id: 1,
        method: "server/discover",
        params: {
          _meta: {
            [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
            [CLIENT_CAPABILITIES_META_KEY]: {},
          },
        },
      });
      const discovered = (await receive(1)) as { result?: { supportedVersions?: string[] } };
      expect(discovered.result?.supportedVersions).toContain("2026-07-28");
      expect(built).toHaveLength(1);

      send({
        jsonrpc: "2.0",
        id: 2,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "legacy-after-discover", version: "0" },
        },
      });
      const initialized = (await receive(2)) as { result?: { protocolVersion?: string } };
      expect(initialized.result?.protocolVersion).toBe("2025-11-25");

      expect(built).toHaveLength(2);
      expect(built[0]).not.toBe(built[1]);
      expect(engine.auditServerStart).toHaveBeenCalledTimes(1);
    } finally {
      await handle.close();
    }
  }, 20_000);
});
