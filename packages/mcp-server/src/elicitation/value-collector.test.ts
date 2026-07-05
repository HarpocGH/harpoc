import { describe, it, expect, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { VaultEngine } from "@harpoc/core";
import { createMcpServer } from "../server.js";
import { startValueCollector, collectValueViaUrlElicitation } from "./value-collector.js";

const FORM_HEADERS = { "content-type": "application/x-www-form-urlencoded" };

function postBody(value: string): string {
  return `value=${encodeURIComponent(value)}`;
}

describe("startValueCollector", () => {
  it("serves the one-time form and collects the posted value", async () => {
    const collector = await startValueCollector({ subject: "my-api-key", operation: "create" });
    try {
      const form = await fetch(collector.url);
      expect(form.status).toBe(200);
      expect(await form.text()).toContain("my-api-key");

      const post = await fetch(collector.url, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("v@l+ue 1"),
      });
      expect(post.status).toBe(200);

      const value = await collector.waitForValue();
      expect(Buffer.from(value).toString("utf8")).toBe("v@l+ue 1");
    } finally {
      await collector.close();
    }
  });

  it("is single-use: the second submission gets 410", async () => {
    const collector = await startValueCollector({ subject: "k", operation: "create" });
    try {
      await fetch(collector.url, { method: "POST", headers: FORM_HEADERS, body: postBody("x") });
      await collector.waitForValue();

      const again = await fetch(collector.url, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("y"),
      });
      expect(again.status).toBe(410);
      const form = await fetch(collector.url);
      expect(form.status).toBe(410);
    } finally {
      await collector.close();
    }
  });

  it("rejects wrong tokens with 404 without settling the wait", async () => {
    const collector = await startValueCollector({ subject: "k", operation: "create" });
    try {
      const base = new URL(collector.url);
      const wrong = `${base.origin}/collect/${"A".repeat(43)}`;
      const res = await fetch(wrong, { method: "POST", headers: FORM_HEADERS, body: postBody("x") });
      expect(res.status).toBe(404);

      const ok = await fetch(collector.url, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("real"),
      });
      expect(ok.status).toBe(200);
      expect(Buffer.from(await collector.waitForValue()).toString("utf8")).toBe("real");
    } finally {
      await collector.close();
    }
  });

  it("rejects empty values with 400 and stays open", async () => {
    const collector = await startValueCollector({ subject: "k", operation: "rotate" });
    try {
      const empty = await fetch(collector.url, {
        method: "POST",
        headers: FORM_HEADERS,
        body: "value=",
      });
      expect(empty.status).toBe(400);

      await fetch(collector.url, { method: "POST", headers: FORM_HEADERS, body: postBody("v2") });
      expect(Buffer.from(await collector.waitForValue()).toString("utf8")).toBe("v2");
    } finally {
      await collector.close();
    }
  });

  it("rejects oversized bodies with 413", async () => {
    const collector = await startValueCollector({ subject: "k", operation: "create" });
    try {
      const res = await fetch(collector.url, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("x".repeat(200 * 1024)),
      });
      expect(res.status).toBe(413);
    } finally {
      await collector.close();
    }
  });

  it("times out the wait", async () => {
    const collector = await startValueCollector({
      subject: "k",
      operation: "create",
      timeoutMs: 50,
    });
    await expect(collector.waitForValue()).rejects.toThrow("timed out");
  });

  it("close() rejects a pending wait and stops the listener", async () => {
    const collector = await startValueCollector({ subject: "k", operation: "create" });
    const wait = collector.waitForValue();
    await collector.close();
    await expect(wait).rejects.toThrow("closed");
    await expect(fetch(collector.url)).rejects.toThrow();
  });
});

describe("collectValueViaUrlElicitation", () => {
  interface FakeServerParts {
    caps: Record<string, unknown> | undefined;
    elicitInput?: ReturnType<typeof vi.fn>;
    notify?: ReturnType<typeof vi.fn>;
  }

  function fakeMcp(parts: FakeServerParts): McpServer {
    const notify = parts.notify ?? vi.fn().mockResolvedValue(undefined);
    return {
      server: {
        getClientCapabilities: () => parts.caps,
        elicitInput: parts.elicitInput ?? vi.fn(),
        createElicitationCompletionNotifier: () => notify,
      },
    } as unknown as McpServer;
  }

  it("returns null when the client declares no elicitation capability", async () => {
    const elicitInput = vi.fn();
    const mcp = fakeMcp({ caps: undefined, elicitInput });
    expect(await collectValueViaUrlElicitation(mcp, { subject: "k", operation: "create" })).toBe(
      null,
    );
    expect(elicitInput).not.toHaveBeenCalled();
  });

  it("returns null for form-only elicitation capability", async () => {
    const elicitInput = vi.fn();
    const mcp = fakeMcp({ caps: { elicitation: { form: {} } }, elicitInput });
    expect(await collectValueViaUrlElicitation(mcp, { subject: "k", operation: "create" })).toBe(
      null,
    );
    expect(elicitInput).not.toHaveBeenCalled();
  });

  it("collects the value when the client accepts and the browser posts", async () => {
    const notify = vi.fn().mockResolvedValue(undefined);
    const elicitInput = vi.fn(async (params: { url: string; message: string }) => {
      expect(params.message).toContain('"my-key"');
      const form = await fetch(params.url);
      expect(form.status).toBe(200);
      const post = await fetch(params.url, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("collected-secret"),
      });
      expect(post.status).toBe(200);
      return { action: "accept" };
    });
    const mcp = fakeMcp({ caps: { elicitation: { url: {} } }, elicitInput, notify });

    const value = await collectValueViaUrlElicitation(mcp, {
      subject: "my-key",
      operation: "create",
    });
    expect(value).not.toBeNull();
    expect(Buffer.from(value as Uint8Array).toString("utf8")).toBe("collected-secret");
    expect(notify).toHaveBeenCalled();
  });

  it("returns null and closes the collector when the user declines", async () => {
    let seenUrl = "";
    const elicitInput = vi.fn((params: { url: string }) => {
      seenUrl = params.url;
      return Promise.resolve({ action: "decline" });
    });
    const mcp = fakeMcp({ caps: { elicitation: { url: {} } }, elicitInput });

    const value = await collectValueViaUrlElicitation(mcp, { subject: "k", operation: "rotate" });
    expect(value).toBe(null);
    await expect(fetch(seenUrl)).rejects.toThrow();
  });

  it("returns null when the elicitation request itself fails", async () => {
    const elicitInput = vi.fn().mockRejectedValue(new Error("client gone"));
    const mcp = fakeMcp({ caps: { elicitation: { url: {} } }, elicitInput });
    expect(await collectValueViaUrlElicitation(mcp, { subject: "k", operation: "create" })).toBe(
      null,
    );
  });
});

describe("URL-mode elicitation end-to-end (InMemory transport)", () => {
  function mockEngine(overrides: Record<string, unknown> = {}): VaultEngine {
    return {
      createSecret: vi
        .fn()
        .mockResolvedValue({ handle: "secret://api-key", status: "pending", message: "" }),
      setSecretValue: vi.fn().mockResolvedValue(undefined),
      rotateSecret: vi.fn().mockResolvedValue(undefined),
      getState: vi.fn().mockReturnValue("unlocked"),
      queryAudit: vi.fn().mockReturnValue([]),
      listSecrets: vi.fn().mockReturnValue([]),
      resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
      ...overrides,
    } as unknown as VaultEngine;
  }

  async function connect(
    engine: VaultEngine,
    clientOptions: ConstructorParameters<typeof Client>[1],
  ): Promise<{ client: Client; close: () => Promise<void> }> {
    const mcpServer = createMcpServer({ engine });
    const client = new Client({ name: "e2e-client", version: "1.0.0" }, clientOptions);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await mcpServer.connect(serverTransport);
    await client.connect(clientTransport);
    return {
      client,
      close: async () => {
        await client.close();
        await mcpServer.close();
      },
    };
  }

  it("create_secret collects the value through the one-time form", async () => {
    const engine = mockEngine();
    let captured = "";
    vi.mocked(engine.setSecretValue).mockImplementation((_handle: string, value: Uint8Array) => {
      captured = Buffer.from(value).toString("utf8");
      return Promise.resolve();
    });

    const { client, close } = await connect(engine, {
      capabilities: { elicitation: { url: {} } },
    });
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      const params = request.params as { mode?: string; url?: string };
      expect(params.mode).toBe("url");
      await fetch(params.url as string);
      await fetch(params.url as string, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("browser-entered-value"),
      });
      return { action: "accept" };
    });

    try {
      const result = (await client.callTool({
        name: "create_secret",
        arguments: { name: "api-key", type: "api_key" },
      })) as { content: Array<{ text: string }> };

      const payload = JSON.parse(result.content[0]?.text ?? "{}") as {
        status: string;
        message: string;
      };
      expect(payload.status).toBe("created");
      expect(engine.setSecretValue).toHaveBeenCalledWith("secret://api-key", expect.anything());
      expect(captured).toBe("browser-entered-value");
      expect(result.content[0]?.text).not.toContain("browser-entered-value");
    } finally {
      await close();
    }
  });

  it("rotate_secret collects the new value through the one-time form", async () => {
    const engine = mockEngine();
    let captured = "";
    vi.mocked(engine.rotateSecret).mockImplementation((_handle: string, value: Uint8Array) => {
      captured = Buffer.from(value).toString("utf8");
      return Promise.resolve();
    });

    const { client, close } = await connect(engine, {
      capabilities: { elicitation: { url: {} } },
    });
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      const params = request.params as { url?: string };
      await fetch(params.url as string, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("rotated-value"),
      });
      return { action: "accept" };
    });

    try {
      const result = (await client.callTool({
        name: "rotate_secret",
        arguments: { handle: "secret://api-key" },
      })) as { content: Array<{ text: string }> };

      const payload = JSON.parse(result.content[0]?.text ?? "{}") as { status: string };
      expect(payload.status).toBe("rotated");
      expect(captured).toBe("rotated-value");
      expect(result.content[0]?.text).not.toContain("rotated-value");
    } finally {
      await close();
    }
  });

  it("falls back to deferred/pending for clients without elicitation.url", async () => {
    const engine = mockEngine();
    const { client, close } = await connect(engine, { capabilities: {} });

    try {
      const created = (await client.callTool({
        name: "create_secret",
        arguments: { name: "api-key", type: "api_key" },
      })) as { content: Array<{ text: string }> };
      const createdPayload = JSON.parse(created.content[0]?.text ?? "{}") as {
        status: string;
        message: string;
      };
      expect(createdPayload.status).toBe("pending");
      expect(createdPayload.message).toContain("harpoc secret set");
      expect(engine.setSecretValue).not.toHaveBeenCalled();

      const rotated = (await client.callTool({
        name: "rotate_secret",
        arguments: { handle: "secret://api-key" },
      })) as { content: Array<{ text: string }> };
      const rotatedPayload = JSON.parse(rotated.content[0]?.text ?? "{}") as { status: string };
      expect(rotatedPayload.status).toBe("pending_rotation");
      expect(engine.rotateSecret).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});
