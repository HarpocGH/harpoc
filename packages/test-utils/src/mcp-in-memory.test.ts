import { describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import {
  connectInMemoryClient,
  connectModernInMemoryClient,
  inMemoryClientFor,
  invokeHandler,
} from "./mcp-in-memory.js";

function serverWithEcho(): McpServer {
  const server = new McpServer({ name: "t", version: "0.0.0" });
  server.registerTool(
    "echo",
    { description: "Echo", inputSchema: z.object({ text: z.string() }) },
    async ({ text }) => ({ content: [{ type: "text" as const, text }] }),
  );
  server.registerTool("boom", { description: "Throws" }, async () => {
    throw new Error("handler failed");
  });
  server.registerResource(
    "r",
    "t://r",
    { description: "R", mimeType: "text/plain" },
    async (uri) => {
      if (uri.href === "t://r") return { contents: [{ uri: uri.href, text: "ok" }] };
      throw new Error("unreachable");
    },
  );
  return server;
}

describe("connectInMemoryClient", () => {
  it("drives tools/list, tools/call and resources/read over the linked pair", async () => {
    const mcp = await connectInMemoryClient(serverWithEcho());
    try {
      expect((await mcp.listTools()).map((t) => t.name).sort()).toEqual(["boom", "echo"]);
      const ok = await mcp.callTool("echo", { text: "hi" });
      expect(ok.isError).toBeUndefined();
      expect(ok.content[0]?.text).toBe("hi");
      const err = await mcp.callTool("boom", {});
      expect(err.isError).toBe(true);
      expect(err.content[0]?.text).toBe("handler failed");
      const refused = await mcp.callTool("echo", { text: 1 });
      expect(refused.isError).toBe(true);
      expect(refused.content[0]?.text).toContain("Invalid arguments for tool echo");
      expect((await mcp.readResource("t://r")).contents[0]?.text).toBe("ok");
    } finally {
      await mcp.close();
    }
  });

  it("inMemoryClientFor hands out a live client again after a close", async () => {
    const server = serverWithEcho();
    const first = await inMemoryClientFor(server);
    await first.close();
    const second = await inMemoryClientFor(server);
    try {
      expect(second).not.toBe(first);
      expect((await second.callTool("echo", { text: "again" })).content[0]?.text).toBe("again");
    } finally {
      await second.close();
    }
  });

  it("inMemoryClientFor memoizes one client per server object", async () => {
    const server = serverWithEcho();
    const other = serverWithEcho();
    const a = await inMemoryClientFor(server);
    const b = await inMemoryClientFor(server);
    const c = await inMemoryClientFor(other);
    try {
      expect(b).toBe(a);
      expect(c).not.toBe(a);
    } finally {
      await a.close();
      await c.close();
    }
  });
  it("inMemoryClientFor clears the memo when the connect rejects, so it stays retryable", async () => {
    const refused = new Error("connect refused");
    let connects = 0;
    const server = {
      connect: async () => {
        connects += 1;
        throw refused;
      },
    } as unknown as McpServer;
    await expect(inMemoryClientFor(server)).rejects.toBe(refused);
    await expect(inMemoryClientFor(server)).rejects.toBe(refused);
    expect(connects).toBe(2);
  });
});

describe("invokeHandler", () => {
  it("reaches a registered handler directly and lets its thrown error through intact", async () => {
    const server = serverWithEcho();
    const marker = new Error("from the resource");
    server.registerResource("bad", "t://bad", { description: "B" }, async () => {
      throw marker;
    });
    await expect(invokeHandler(server, "resources/read", { uri: "t://bad" })).rejects.toBe(marker);
    const read = (await invokeHandler(server, "resources/read", { uri: "t://r" })) as {
      contents: Array<{ text?: string }>;
    };
    expect(read.contents[0]?.text).toBe("ok");
  });
});

function eraServer(): McpServer {
  const server = new McpServer({ name: "t", version: "1.0.0" });
  server.registerTool("era", { description: "era" }, async (ctx) => ({
    content: [
      { type: "text" as const, text: ctx.mcpReq.envelope !== undefined ? "modern" : "legacy" },
    ],
  }));
  return server;
}

describe("connectModernInMemoryClient", () => {
  it("serves the modern era at the pinned revision", async () => {
    const mcp = await connectModernInMemoryClient(eraServer);
    try {
      expect((await mcp.callTool("era", {})).content[0]?.text).toBe("modern");
      expect(mcp.client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
      expect(mcp.client.getProtocolEra()).toBe("modern");
    } finally {
      await mcp.close();
    }
  });

  it("contrasts with the legacy helper over the bare pair", async () => {
    const mcp = await connectInMemoryClient(eraServer());
    try {
      expect((await mcp.callTool("era", {})).content[0]?.text).toBe("legacy");
      expect(mcp.client.getNegotiatedProtocolVersion()).toBe("2025-11-25");
    } finally {
      await mcp.close();
    }
  });

  it("closes the client and the serveStdio handle, and a second close does not throw", async () => {
    const mcp = await connectModernInMemoryClient(eraServer);
    expect((await mcp.callTool("era", {})).content[0]?.text).toBe("modern");
    await expect(mcp.close()).resolves.toBeUndefined();
    await expect(mcp.callTool("era", {})).rejects.toThrow();
    await expect(mcp.close()).resolves.toBeUndefined();
  });
});
