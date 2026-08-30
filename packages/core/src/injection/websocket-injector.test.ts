import { afterEach, describe, expect, it } from "vitest";
import type { InjectionPolicy, InjectionPolicyInput, WebsocketAction } from "@harpoc/shared";
import {
  ActionType,
  ErrorCode,
  VaultError,
  injectionPolicyInputSchema,
  websocketActionSchema,
} from "@harpoc/shared";
import type { FakeWsServer, FakeWsScript } from "./__fixtures__/fake-ws-server.js";
import { startFakeWsServer } from "./__fixtures__/fake-ws-server.js";
import { buildWsAuditDetails, executeWebsocketAction } from "./websocket-injector.js";

const SECRET = "ws-secret-value";

function baseAction(partial: Record<string, unknown> = {}): WebsocketAction {
  return {
    type: ActionType.WEBSOCKET,
    url: "ws://127.0.0.1:0/",
    injection: { type: "bearer" },
    ...partial,
  } as unknown as WebsocketAction;
}

function basePolicy(partial: Partial<InjectionPolicyInput> = {}): InjectionPolicy {
  return injectionPolicyInputSchema.parse(partial);
}

function secretBytes(value = SECRET): Uint8Array {
  return new TextEncoder().encode(value);
}

let server: FakeWsServer | undefined;

async function start(script: FakeWsScript): Promise<FakeWsServer> {
  server = await startFakeWsServer(script);
  return server;
}

afterEach(async () => {
  if (server) {
    await server.close();
    server = undefined;
  }
});

describe("executeWebsocketAction — handshake credential injection", () => {
  it("carries a bearer credential in the Authorization header at the handshake", async () => {
    const fake = await start({});
    const action = baseAction({ url: `ws://127.0.0.1:${fake.port}/` });

    await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(fake.requests()).toHaveLength(1);
    expect(fake.requests()[0]?.headers.authorization).toBe(`Bearer ${SECRET}`);
  });

  it("carries a named header credential at the handshake", async () => {
    const fake = await start({});
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      injection: { type: "header", header_name: "X-Api-Key" },
    });

    await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(fake.requests()[0]?.headers["x-api-key"]).toBe(SECRET);
  });

  it("carries a query-param credential in the handshake URL", async () => {
    const fake = await start({});
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/connect`,
      injection: { type: "query", query_param: "token" },
    });

    await executeWebsocketAction(action, secretBytes(), basePolicy());

    const seenUrl = fake.requests()[0]?.url ?? "";
    expect(seenUrl).toContain(`token=${SECRET}`);
  });

  it("never places the credential in a sent frame", async () => {
    const fake = await start({});
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      message: "hello from the vault",
    });

    await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(fake.clientFrames()).toHaveLength(1);
    expect(fake.clientFrames()[0]?.payload.toString("utf8")).toBe("hello from the vault");
    expect(fake.clientFrames()[0]?.payload.toString("utf8")).not.toContain(SECRET);
  });
});

describe("executeWebsocketAction — bounded collect", () => {
  it("stops at max_messages when the server sends more", async () => {
    const fake = await start({ messages: ["m1", "m2", "m3", "m4", "m5"] });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      collect: { max_messages: 2, window_ms: 5_000 },
    });

    const { result } = await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(result.messages).toEqual(["m1", "m2"]);
  });

  it("stops at window_ms when the server stalls after fewer than max_messages", async () => {
    const fake = await start({ messages: ["only"], stall: true });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      collect: { max_messages: 5, window_ms: 150 },
    });

    const start2 = Date.now();
    const { result } = await executeWebsocketAction(action, secretBytes(), basePolicy());
    const elapsed = Date.now() - start2;

    expect(result.messages).toEqual(["only"]);
    expect(elapsed).toBeGreaterThanOrEqual(140);
  }, 10_000);

  it("defaults to max_messages=1 when collect is not specified", async () => {
    const fake = await start({ messages: ["first", "second"] });
    const action = baseAction({ url: `ws://127.0.0.1:${fake.port}/` });

    const { result } = await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(result.messages).toEqual(["first"]);
  });
});

describe("executeWebsocketAction — bounded close wait", () => {
  it("still resolves within timeout_ms when the server never completes the closing handshake", async () => {
    // Regression for the `waitWithTimeout` guard: a server that accepts the
    // connection, never sends anything, and then swallows our Close frame
    // (never acking it, never ending the TCP connection) must not hang the
    // exchange forever. Without the guard, this test hangs until vitest's
    // own test timeout — it does not fail cleanly with a bounded elapsed time.
    const fake = await start({ stall: true, neverAckClose: true });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      timeout_ms: 200,
      collect: { max_messages: 1, window_ms: 50 },
    });

    const started = Date.now();
    const { result } = await executeWebsocketAction(action, secretBytes(), basePolicy());
    const elapsed = Date.now() - started;

    // No server Close frame was ever received, so undici's `close` event
    // never fires — the close code the injector observed is null.
    expect(result.close_code).toBeNull();
    // Bounded by collect's window_ms (50) plus the close-wait timeout (200),
    // not by vitest's own test timeout — proves the guard is what ended it.
    expect(elapsed).toBeGreaterThanOrEqual(230);
    expect(elapsed).toBeLessThan(3_000);
  }, 10_000);
});

describe("executeWebsocketAction — response_mode shaping", () => {
  it("redacts the credential from frames under filtered (the default)", async () => {
    const fake = await start({ messages: [`echo: ${SECRET}`] });
    const action = baseAction({ url: `ws://127.0.0.1:${fake.port}/` });

    const { result } = await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(result.messages[0]).not.toContain(SECRET);
    expect(result.messages[0]).toContain("[REDACTED]");
  });

  // E70: the redaction is invisible in the wire result, so the execution
  // reports it and the engine stamps its success row from that.
  it("reports sanitized when a frame carried the credential", async () => {
    const fake = await start({ messages: [`echo: ${SECRET}`] });
    const action = baseAction({ url: `ws://127.0.0.1:${fake.port}/` });

    const execution = await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(execution.sanitized).toBe(true);
  });

  it("reports sanitized false under full, which redacts nothing", async () => {
    const fake = await start({ messages: [`echo: ${SECRET}`] });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      response_mode: "full",
    });

    const execution = await executeWebsocketAction(
      action,
      secretBytes(),
      basePolicy({ response_mode: "full" }),
    );

    expect(execution.sanitized).toBe(false);
  });

  it("returns frames verbatim under full", async () => {
    const fake = await start({ messages: [`echo: ${SECRET}`] });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      response_mode: "full",
    });

    const { result } = await executeWebsocketAction(
      action,
      secretBytes(),
      basePolicy({ response_mode: "full" }),
    );

    expect(result.messages[0]).toBe(`echo: ${SECRET}`);
  });

  it("returns no messages under status_only, only the close code", async () => {
    const fake = await start({ messages: [`echo: ${SECRET}`] });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      response_mode: "status_only",
    });

    const { result } = await executeWebsocketAction(action, secretBytes(), basePolicy());

    expect(result.messages).toEqual([]);
    expect(result.close_code).not.toBeNull();
  });

  it("refuses a loosening per-invocation override BEFORE dialing (RESPONSE_MODE_NOT_ALLOWED)", async () => {
    const fake = await start({});
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      response_mode: "full",
    });

    await expect(
      executeWebsocketAction(action, secretBytes(), basePolicy({ response_mode: "filtered" })),
    ).rejects.toMatchObject({ code: ErrorCode.RESPONSE_MODE_NOT_ALLOWED });

    // Before dialing: no connection ever reached the fake server.
    expect(fake.requests()).toHaveLength(0);
  });

  it("allows a tightening per-invocation override (status_only under a filtered floor)", async () => {
    const fake = await start({ messages: ["m1"] });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      response_mode: "status_only",
    });

    await expect(
      executeWebsocketAction(action, secretBytes(), basePolicy({ response_mode: "filtered" })),
    ).resolves.toMatchObject({ result: { messages: [] } });
  });
});

describe("executeWebsocketAction — non-101 / connection failure", () => {
  it("refuses a generic non-101 handshake response as WEBSOCKET_CONNECT_FAILED", async () => {
    const fake = await start({ respondStatus: 400 });
    const action = baseAction({ url: `ws://127.0.0.1:${fake.port}/` });

    await expect(executeWebsocketAction(action, secretBytes(), basePolicy())).rejects.toMatchObject(
      { code: ErrorCode.WEBSOCKET_CONNECT_FAILED },
    );
  });

  it("never follows a 3xx handshake response — refuses as WEBSOCKET_CONNECT_FAILED", async () => {
    const fake = await start({ respondStatus: 302 });
    const action = baseAction({ url: `ws://127.0.0.1:${fake.port}/` });

    await expect(executeWebsocketAction(action, secretBytes(), basePolicy())).rejects.toMatchObject(
      { code: ErrorCode.WEBSOCKET_CONNECT_FAILED },
    );

    // Exactly one request — the redirect target was never dialed.
    expect(fake.requests()).toHaveLength(1);
  });

  it("refuses a refused connection (nothing listening) as WEBSOCKET_CONNECT_FAILED", async () => {
    const action = baseAction({ url: "ws://127.0.0.1:1/" });

    await expect(executeWebsocketAction(action, secretBytes(), basePolicy())).rejects.toMatchObject(
      { code: ErrorCode.WEBSOCKET_CONNECT_FAILED },
    );
  });

  it("does not leak the credential in a thrown error's message", async () => {
    const fake = await start({ respondStatus: 400 });
    const action = baseAction({
      url: `ws://127.0.0.1:${fake.port}/`,
      injection: { type: "query", query_param: "token" },
    });

    let thrown: unknown;
    try {
      await executeWebsocketAction(action, secretBytes(), basePolicy());
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect((thrown as VaultError).message).not.toContain(SECRET);
  });
});

describe("executeWebsocketAction — schema-level scope (Task 1)", () => {
  it("refuses a non-loopback ws:// URL at the schema boundary", () => {
    const result = websocketActionSchema.safeParse({
      type: ActionType.WEBSOCKET,
      url: "ws://example.com/",
      injection: { type: "bearer" },
    });
    expect(result.success).toBe(false);
  });

  it("accepts a non-loopback wss:// URL at the schema boundary", () => {
    const result = websocketActionSchema.safeParse({
      type: ActionType.WEBSOCKET,
      url: "wss://example.com/",
      injection: { type: "bearer" },
    });
    expect(result.success).toBe(true);
  });
});

describe("buildWsAuditDetails", () => {
  it("projects url, whether a message was sent, and the messages actually received", () => {
    const action = baseAction({ url: "ws://127.0.0.1:9/", message: "hi" });
    const details = buildWsAuditDetails(action, { messages: ["a", "b"], close_code: 1000 });
    expect(details).toEqual({ url: "ws://127.0.0.1:9/", sent: 1, received: 2 });
  });

  it("reports sent: 0 when no message was configured", () => {
    const action = baseAction({ url: "ws://127.0.0.1:9/" });
    const details = buildWsAuditDetails(action, { messages: [], close_code: 1000 });
    expect(details.sent).toBe(0);
  });
});
