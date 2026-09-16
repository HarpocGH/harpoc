import { describe, it, expect, vi } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { CLIENT_CAPABILITIES_META_KEY, InMemoryTransport } from "@modelcontextprotocol/server";
import type { McpServer, ServerContext } from "@modelcontextprotocol/server";
import { connectModernInMemoryClient } from "@harpoc/test-utils";
import type { InMemoryMcpClient } from "@harpoc/test-utils";
import type { VaultEngine } from "@harpoc/core";
import { VaultError } from "@harpoc/shared";
import { createMcpServer } from "../server.js";
import { valueRequestState } from "./request-state.js";
import * as ttyPrompt from "./tty-prompt.js";
import * as valueCollector from "./value-collector.js";
import {
  collectValueViaUrlElicitation,
  elicitValueViaInputRequired,
  startValueCollector,
} from "./value-collector.js";

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
      const res = await fetch(wrong, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("x"),
      });
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

/**
 * M10. (a) `timingSafeEqual` throws ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH on
 * unequal lengths, and the length guard in matchesToken was the only thing
 * standing between a short URL token and an unhandled throw out of a
 * synchronous node:http handler — which takes the whole vault process down.
 * (b) Nothing bounded how many collectors could be live at once, each pinning
 * a loopback listener and a five-minute timer.
 */
describe("startValueCollector — request-handler robustness (M10a)", () => {
  const tokenLengths = [0, 1, 20, 42, 44, 200];

  it("answers 404 for every wrong token length and stays serving", async () => {
    const collector = await startValueCollector({ subject: "k", operation: "create" });
    try {
      const base = new URL(collector.url).origin;
      for (const len of tokenLengths) {
        const res = await fetch(`${base}/collect/${"A".repeat(len)}`);
        expect(res.status).toBe(404);
      }

      // Still healthy: neither the process nor the listener went down.
      const ok = await fetch(collector.url, {
        method: "POST",
        headers: FORM_HEADERS,
        body: postBody("still-working"),
      });
      expect(ok.status).toBe(200);
      expect(Buffer.from(await collector.waitForValue()).toString("utf8")).toBe("still-working");
    } finally {
      await collector.close();
    }
  });

  it("answers 404 for a path outside the collect prefix", async () => {
    const collector = await startValueCollector({ subject: "k", operation: "create" });
    try {
      const base = new URL(collector.url).origin;
      expect((await fetch(`${base}/`)).status).toBe(404);
      expect((await fetch(`${base}/collect`)).status).toBe(404);
    } finally {
      await collector.close();
    }
  });
});

describe("startValueCollector — concurrency ceiling (M10b)", () => {
  it("refuses to open more collectors than the ceiling, and recovers as they close", async () => {
    const open: Awaited<ReturnType<typeof startValueCollector>>[] = [];
    try {
      for (let i = 0; i < 8; i++) {
        open.push(await startValueCollector({ subject: `k${String(i)}`, operation: "create" }));
      }

      await expect(
        startValueCollector({ subject: "overflow", operation: "create" }),
      ).rejects.toThrow(/concurrent value collectors/);

      // Closing one frees exactly one slot.
      await (open.pop() as Awaited<ReturnType<typeof startValueCollector>>).close();
      const refilled = await startValueCollector({ subject: "refill", operation: "create" });
      open.push(refilled);
    } finally {
      for (const collector of open) await collector.close();
    }
  }, 20_000);

  it("a caller degrades gracefully when the ceiling is reached", async () => {
    const open: Awaited<ReturnType<typeof startValueCollector>>[] = [];
    try {
      for (let i = 0; i < 8; i++) {
        open.push(await startValueCollector({ subject: `k${String(i)}`, operation: "create" }));
      }

      // The elicitation caller must fall through to the next channel rather
      // than surfacing an error to the agent.
      const mcp = {
        server: {
          getClientCapabilities: () => ({ elicitation: { url: true } }),
          elicitInput: vi.fn(),
        },
      } as unknown as McpServer;

      await expect(
        collectValueViaUrlElicitation(mcp, { subject: "x", operation: "create" }),
      ).resolves.toBeNull();
    } finally {
      for (const collector of open) await collector.close();
    }
  }, 20_000);
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
      auditServerStart: vi.fn(),
      ...overrides,
    } as unknown as VaultEngine;
  }

  async function connect(
    engine: VaultEngine,
    clientOptions: ConstructorParameters<typeof Client>[1],
  ): Promise<{ client: Client; close: () => Promise<void> }> {
    const mcpServer = createMcpServer({ engine, allowTokenless: true });
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
    client.setRequestHandler("elicitation/create", async (request) => {
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
      expect(engine.setSecretValue).toHaveBeenCalledWith(
        "secret://api-key",
        expect.anything(),
        expect.objectContaining({
          principal_type: "user",
          principal_id: "tokenless-stdio",
          admin_scope: true,
        }),
      );
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
    client.setRequestHandler("elicitation/create", async (request) => {
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

  describe("the modern (2026-07-28) leg", () => {
    async function connectModern(
      engine: VaultEngine,
      enableTtyPrompt = false,
    ): Promise<InMemoryMcpClient> {
      return connectModernInMemoryClient(
        () => createMcpServer({ engine, allowTokenless: true, enableTtyPrompt }),
        { name: "e2e-client", version: "1.0.0" },
        { capabilities: { elicitation: { url: {} } } },
      );
    }

    async function connectModernWithToken(
      engine: VaultEngine,
      launchToken: string,
    ): Promise<InMemoryMcpClient> {
      return connectModernInMemoryClient(
        () => createMcpServer({ engine, launchToken }),
        { name: "e2e-client", version: "1.0.0" },
        { capabilities: { elicitation: { url: {} } } },
      );
    }

    function modernCtx(): ServerContext {
      return {
        mcpReq: {
          envelope: { [CLIENT_CAPABILITIES_META_KEY]: { elicitation: { url: {} } } },
        },
      } as unknown as ServerContext;
    }

    async function retryRaw(
      modern: InMemoryMcpClient,
      requestState: unknown,
      action: "accept" | "decline",
      args: Record<string, unknown> = { name: "api-key", type: "api_key" },
    ): Promise<{ isError?: boolean; content: Array<{ text?: string }> }> {
      return (await modern.client.request({
        method: "tools/call",
        params: {
          name: "create_secret",
          arguments: args,
          requestState,
          inputResponses: { value: { action } },
        },
      })) as unknown as { isError?: boolean; content: Array<{ text?: string }> };
    }

    it("create_secret round-trips the value through the one-time form", async () => {
      const engine = mockEngine();
      let captured = "";
      vi.mocked(engine.setSecretValue).mockImplementation((_handle: string, value: Uint8Array) => {
        captured = Buffer.from(value).toString("utf8");
        return Promise.resolve();
      });

      const modern = await connectModern(engine);
      modern.client.setRequestHandler("elicitation/create", async (request) => {
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
        const result = await modern.callTool("create_secret", {
          name: "api-key",
          type: "api_key",
        });
        const payload = JSON.parse(result.content[0]?.text ?? "{}") as { status: string };
        expect(payload.status).toBe("created");
        expect(engine.setSecretValue).toHaveBeenCalledWith(
          "secret://api-key",
          expect.anything(),
          expect.objectContaining({ principal_id: "tokenless-stdio" }),
        );
        expect(captured).toBe("browser-entered-value");
        expect(result.content[0]?.text).not.toContain("browser-entered-value");
      } finally {
        await modern.close();
      }
    });

    it("create_secret stays pending when the client declines", async () => {
      const engine = mockEngine();
      const modern = await connectModern(engine);
      modern.client.setRequestHandler("elicitation/create", () =>
        Promise.resolve({ action: "decline" as const }),
      );

      try {
        const result = await modern.callTool("create_secret", {
          name: "api-key",
          type: "api_key",
        });
        const payload = JSON.parse(result.content[0]?.text ?? "{}") as {
          status: string;
          message: string;
        };
        expect(payload.status).toBe("pending");
        expect(payload.message).toContain("harpoc secret set");
        expect(engine.setSecretValue).not.toHaveBeenCalled();
      } finally {
        await modern.close();
      }
    });

    it("refuses a tampered requestState before the tool runs", async () => {
      const engine = mockEngine();
      const verify = vi.spyOn(valueRequestState, "verify").mockRejectedValue(new Error("mac"));
      const modern = await connectModern(engine);
      modern.client.setRequestHandler("elicitation/create", () =>
        Promise.resolve({ action: "accept" as const }),
      );

      try {
        let thrown: unknown;
        try {
          await modern.callTool("create_secret", { name: "api-key", type: "api_key" });
        } catch (err) {
          thrown = err;
        }
        expect((thrown as { code?: number }).code).toBe(-32602);
        expect(String((thrown as { message?: string }).message)).toContain(
          "Invalid or expired requestState",
        );
        expect(engine.createSecret).not.toHaveBeenCalled();

        const genuine = verify.mock.calls[0]?.[0];
        verify.mockRestore();
        const drained = await retryRaw(modern, genuine, "decline");
        expect(drained.isError).toBeUndefined();
      } finally {
        verify.mockRestore();
        await modern.close();
      }
    });

    it("refuses a genuine requestState with one character flipped", async () => {
      const engine = mockEngine();
      let captured = "";
      vi.mocked(engine.setSecretValue).mockImplementation((_handle: string, value: Uint8Array) => {
        captured = Buffer.from(value).toString("utf8");
        return Promise.resolve();
      });

      const modern = await connectModern(engine);
      try {
        const round1 = (await modern.client.request(
          {
            method: "tools/call",
            params: { name: "create_secret", arguments: { name: "api-key", type: "api_key" } },
          },
          { allowInputRequired: true },
        )) as unknown as {
          resultType?: string;
          requestState?: string;
          inputRequests?: { value?: { params?: { url?: string } } };
        };
        expect(round1.resultType).toBe("input_required");
        const genuine = round1.requestState ?? "";
        await fetch(round1.inputRequests?.value?.params?.url ?? "", {
          method: "POST",
          headers: FORM_HEADERS,
          body: postBody("value-behind-the-mac"),
        });

        const middle = Math.floor(genuine.length / 2);
        const at = genuine.slice(middle, middle + 1);
        expect(at).toMatch(/[A-Za-z0-9_-]/);
        const flipped =
          genuine.slice(0, middle) + (at === "a" ? "b" : "a") + genuine.slice(middle + 1);
        expect(flipped.length).toBe(genuine.length);
        expect(flipped).not.toBe(genuine);

        let thrown: unknown;
        try {
          await retryRaw(modern, flipped, "accept");
        } catch (err) {
          thrown = err;
        }
        expect((thrown as { code?: number }).code).toBe(-32602);
        expect(String((thrown as { message?: string }).message)).toContain(
          "Invalid or expired requestState",
        );
        expect(engine.createSecret).not.toHaveBeenCalled();

        const genuineRetry = await retryRaw(modern, genuine, "accept");
        expect(genuineRetry.isError).toBeUndefined();
        expect(captured).toBe("value-behind-the-mac");
      } finally {
        await modern.close();
      }
    });

    it("refuses a requestState whose collector has already closed", async () => {
      const engine = mockEngine();
      const pending = await elicitValueViaInputRequired(
        {
          subject: "api-key",
          operation: "create",
          principal: "tokenless-stdio",
          target: "/api-key",
          timeoutMs: 50,
        },
        modernCtx(),
      );
      const requestState = pending?.requestState;
      expect(typeof requestState).toBe("string");
      await new Promise((resolve) => setTimeout(resolve, 150));

      const modern = await connectModern(engine);
      try {
        const result = await retryRaw(modern, requestState, "accept");
        expect(result.isError).toBe(true);
        expect(result.content[0]?.text).toContain(
          "requestState names no live value collection for this caller",
        );
        expect(engine.createSecret).not.toHaveBeenCalled();
      } finally {
        await modern.close();
      }
    });

    it("refuses a requestState minted by a token-bearing caller named local", async () => {
      const engine = mockEngine({
        verifyToken: vi.fn().mockReturnValue({
          sub: "local",
          vault_id: "v",
          scope: ["admin"],
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          jti: "01931b7e-0000-7000-8000-00000000cafe",
          principal_type: "agent",
        }),
        isTokenRevoked: vi.fn().mockReturnValue(false),
      });

      const tokenBearing = await connectModernWithToken(engine, "local.jwt.token");
      try {
        const round1 = (await tokenBearing.client.request(
          {
            method: "tools/call",
            params: { name: "create_secret", arguments: { name: "api-key", type: "api_key" } },
          },
          { allowInputRequired: true },
        )) as unknown as {
          resultType?: string;
          requestState?: string;
          inputRequests?: { value?: { params?: { url?: string } } };
        };
        expect(round1.resultType).toBe("input_required");
        const url = round1.inputRequests?.value?.params?.url ?? "";
        await fetch(url, {
          method: "POST",
          headers: FORM_HEADERS,
          body: postBody("typed-into-the-local-token-form"),
        });

        const modern = await connectModern(engine);
        try {
          const result = await retryRaw(modern, round1.requestState, "accept");
          expect(result.isError).toBe(true);
          expect(result.content[0]?.text).toContain(
            "requestState names no live value collection for this caller",
          );
          expect(engine.createSecret).not.toHaveBeenCalled();
          expect(engine.setSecretValue).not.toHaveBeenCalled();
        } finally {
          await modern.close();
        }
      } finally {
        await tokenBearing.close();
      }
    });

    it("rotate_secret round-trips the new value through the one-time form", async () => {
      const engine = mockEngine();
      let captured = "";
      vi.mocked(engine.rotateSecret).mockImplementation((_handle: string, value: Uint8Array) => {
        captured = Buffer.from(value).toString("utf8");
        return Promise.resolve();
      });

      const modern = await connectModern(engine);
      modern.client.setRequestHandler("elicitation/create", async (request) => {
        const params = request.params as { mode?: string; url?: string };
        expect(params.mode).toBe("url");
        await fetch(params.url as string, {
          method: "POST",
          headers: FORM_HEADERS,
          body: postBody("rotated-value"),
        });
        return { action: "accept" };
      });

      try {
        const result = await modern.callTool("rotate_secret", { handle: "secret://api-key" });
        const payload = JSON.parse(result.content[0]?.text ?? "{}") as { status: string };
        expect(payload.status).toBe("rotated");
        expect(captured).toBe("rotated-value");
        expect(result.content[0]?.text).not.toContain("rotated-value");
      } finally {
        await modern.close();
      }
    });

    it("rotate_secret stays pending_rotation when the client declines", async () => {
      const engine = mockEngine();
      const modern = await connectModern(engine);
      modern.client.setRequestHandler("elicitation/create", () =>
        Promise.resolve({ action: "decline" as const }),
      );

      try {
        const result = await modern.callTool("rotate_secret", { handle: "secret://api-key" });
        const payload = JSON.parse(result.content[0]?.text ?? "{}") as { status: string };
        expect(payload.status).toBe("pending_rotation");
        expect(engine.rotateSecret).not.toHaveBeenCalled();
      } finally {
        await modern.close();
      }
    });

    it("refuses a requestState replayed into another operation and subject", async () => {
      const engine = mockEngine();
      const pending = await elicitValueViaInputRequired(
        {
          subject: "db-password",
          operation: "rotate",
          principal: "tokenless-stdio",
          target: "/db-password",
        },
        modernCtx(),
      );
      const requestState = pending?.requestState;
      const url = (pending?.inputRequests?.value as { params?: { url?: string } } | undefined)
        ?.params?.url;
      expect(typeof requestState).toBe("string");
      expect(typeof url).toBe("string");

      const modern = await connectModern(engine);
      try {
        const replayed = await retryRaw(modern, requestState, "accept");
        expect(replayed.isError).toBe(true);
        expect(replayed.content[0]?.text).toContain(
          "requestState names no live value collection for this caller",
        );
        expect(engine.createSecret).not.toHaveBeenCalled();

        await expect(fetch(url as string)).rejects.toThrow();
        const again = await retryRaw(modern, requestState, "accept");
        expect(again.isError).toBe(true);
      } finally {
        await modern.close();
      }
    });

    it("refuses a requestState replayed into another project", async () => {
      const engine = mockEngine();
      const modern = await connectModern(engine);
      try {
        const round1 = (await modern.client.request(
          {
            method: "tools/call",
            params: {
              name: "create_secret",
              arguments: { name: "api-key", type: "api_key", project: "prod" },
            },
          },
          { allowInputRequired: true },
        )) as unknown as { resultType?: string; requestState?: string };
        expect(round1.resultType).toBe("input_required");

        const replayed = await retryRaw(modern, round1.requestState, "accept", {
          name: "api-key",
          type: "api_key",
          project: "staging",
        });
        expect(replayed.isError).toBe(true);
        expect(replayed.content[0]?.text).toContain(
          "requestState names no live value collection for this caller",
        );
        expect(engine.createSecret).not.toHaveBeenCalled();
      } finally {
        await modern.close();
      }
    });

    it("zeroes the collected value when the engine refuses the create on the retry", async () => {
      const engine = mockEngine();
      vi.mocked(engine.createSecret).mockRejectedValue(VaultError.duplicateSecret("api-key"));
      const resumed = vi.spyOn(valueCollector, "resumeValueCollection");

      const modern = await connectModern(engine);
      modern.client.setRequestHandler("elicitation/create", async (request) => {
        const params = request.params as { url?: string };
        await fetch(params.url as string, {
          method: "POST",
          headers: FORM_HEADERS,
          body: postBody("value-the-engine-refuses"),
        });
        return { action: "accept" };
      });

      try {
        const result = await modern.callTool("create_secret", {
          name: "api-key",
          type: "api_key",
        });
        expect(result.isError).toBe(true);
        expect(result.content[0]?.text).toContain("Secret already exists");

        const collected = (await resumed.mock.results[0]?.value) as Uint8Array;
        expect(collected.length).toBe("value-the-engine-refuses".length);
        expect(collected.every((byte) => byte === 0)).toBe(true);
      } finally {
        resumed.mockRestore();
        await modern.close();
      }
    });

    it("hands the client a URL-mode request and a value-free request state", async () => {
      const pending = await elicitValueViaInputRequired(
        {
          subject: "api-key",
          operation: "create",
          principal: "tokenless-stdio",
          target: "prod/api-key",
          timeoutMs: 50,
        },
        modernCtx(),
      );

      const request = pending?.inputRequests?.value as
        | { params?: { mode?: string; url?: string; message?: string } }
        | undefined;
      expect(request?.params?.mode).toBe("url");
      const url = request?.params?.url ?? "";
      expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/collect\/[A-Za-z0-9_-]{43}$/);
      expect(request?.params?.message).toBe(
        'Enter the value for secret "api-key" in the one-time local form. The value is posted directly to the vault and never enters the model context.',
      );

      const segments = (pending?.requestState ?? "").split(".");
      expect(segments[0]).toBe("v1");
      const envelope = JSON.parse(Buffer.from(segments[1] ?? "", "base64url").toString("utf8")) as {
        p: Record<string, unknown>;
      };
      expect(Object.keys(envelope.p).sort()).toEqual([
        "collector",
        "operation",
        "principal",
        "target",
      ]);
      expect(envelope.p).toMatchObject({
        principal: "tokenless-stdio",
        operation: "create",
        target: "prod/api-key",
      });
      expect(pending?.requestState).not.toContain(url.slice(url.lastIndexOf("/") + 1));

      await new Promise((resolve) => setTimeout(resolve, 150));
    });

    it("falls to the terminal prompt when a modern retry declines", async () => {
      const engine = mockEngine();
      const tty = vi
        .spyOn(ttyPrompt, "collectValueFromTty")
        .mockResolvedValue(new Uint8Array(Buffer.from("typed-at-the-terminal", "utf8")));
      let captured = "";
      vi.mocked(engine.setSecretValue).mockImplementation((_handle: string, value: Uint8Array) => {
        captured = Buffer.from(value).toString("utf8");
        return Promise.resolve();
      });

      const modern = await connectModern(engine, true);
      modern.client.setRequestHandler("elicitation/create", () =>
        Promise.resolve({ action: "decline" as const }),
      );

      try {
        const result = await modern.callTool("create_secret", {
          name: "api-key",
          type: "api_key",
        });
        const payload = JSON.parse(result.content[0]?.text ?? "{}") as {
          status: string;
          message: string;
        };
        expect(payload.status).toBe("created");
        expect(payload.message).toContain("a terminal prompt");
        expect(tty).toHaveBeenCalledWith({ subject: "api-key", operation: "create" });
        expect(captured).toBe("typed-at-the-terminal");
      } finally {
        tty.mockRestore();
        await modern.close();
      }
    });
  });
});
