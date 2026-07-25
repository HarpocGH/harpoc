import { afterEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { CallbackServer } from "./callback-server.js";

let server: CallbackServer | null = null;

afterEach(async () => {
  if (server) {
    await server.stop();
    server = null;
  }
});

describe("CallbackServer", () => {
  /**
   * T15: the loopback-only bind — what keeps an in-flight OAuth authorization
   * code (and the PKCE-completing redirect) off the LAN — was asserted by
   * nothing. Dropping the hostname argument makes Node bind every interface
   * while every existing test, which talks to 127.0.0.1, stays green.
   */
  it("binds loopback only, never every interface", async () => {
    server = new CallbackServer(0);
    await server.start("state-for-bind-check", 5000);

    const underlying = (server as unknown as { server: { address(): unknown } }).server;
    const address = underlying.address() as { address: string; family: string; port: number };

    expect(address.address).toBe("127.0.0.1");
    expect(address.family).toBe("IPv4");
    // "0.0.0.0" and "::" are the wildcard binds an omitted hostname produces.
    expect(["0.0.0.0", "::"]).not.toContain(address.address);
    expect(address.port).toBe(server.listenPort);
  });

  it("starts and stops cleanly", async () => {
    server = new CallbackServer(0);
    const state = "abc123";

    await server.start(state, 5000);
    expect(server.isRunning).toBe(true);

    const port = server.listenPort;
    expect(port).toBeGreaterThan(0);

    const callbackPromise = server.waitForCallback();
    const url = `http://127.0.0.1:${port}/oauth/callback?code=test-code&state=${state}`;
    const res = await fetch(url);
    expect(res.status).toBe(200);

    const result = await callbackPromise;
    expect(result.code).toBe("test-code");
    expect(result.state).toBe(state);
  });

  it("rejects mismatched state", async () => {
    server = new CallbackServer(0);
    const state = "expected-state-value-exactly-64-hex-characters-here0123456789ab";

    await server.start(state, 5000);
    const callbackPromise = server.waitForCallback();
    // Prevent Node.js from treating this as unhandled
    callbackPromise.catch(() => {});

    const port = server.listenPort;
    await fetch(
      `http://127.0.0.1:${port}/oauth/callback?code=test&state=wrong-state-value-that-doesnt-match-expected-64-hex-chars-here`,
    );

    await expect(callbackPromise).rejects.toMatchObject({
      code: ErrorCode.OAUTH_INVALID_STATE,
    });
  });

  it("handles missing code parameter", async () => {
    server = new CallbackServer(0);
    const state = "state123";

    await server.start(state, 5000);
    const callbackPromise = server.waitForCallback();
    callbackPromise.catch(() => {});

    const port = server.listenPort;
    await fetch(`http://127.0.0.1:${port}/oauth/callback?state=${state}`);

    await expect(callbackPromise).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });
  });

  it("handles error parameter from provider", async () => {
    server = new CallbackServer(0);
    const state = "state123";

    await server.start(state, 5000);
    const callbackPromise = server.waitForCallback();
    callbackPromise.catch(() => {});

    const port = server.listenPort;
    await fetch(
      `http://127.0.0.1:${port}/oauth/callback?error=access_denied&error_description=User+denied+access`,
    );

    await expect(callbackPromise).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });
  });

  it("times out when no callback received", async () => {
    server = new CallbackServer(0);
    const state = "timeout-state";

    await server.start(state, 100);
    const callbackPromise = server.waitForCallback();
    callbackPromise.catch(() => {});

    await expect(callbackPromise).rejects.toMatchObject({
      code: ErrorCode.OAUTH_CALLBACK_TIMEOUT,
    });
  });

  it("rejects starting when already running", async () => {
    server = new CallbackServer(0);
    const state = "state1";

    await server.start(state, 5000);

    await expect(server.start("state2", 5000)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });

    // Clean up: send callback to resolve the first start
    const port = server.listenPort;
    await fetch(`http://127.0.0.1:${port}/oauth/callback?code=x&state=${state}`);
    await server.waitForCallback();
  });

  it("stop is idempotent", async () => {
    server = new CallbackServer(0);
    await server.stop(); // not running — should be safe
    await server.stop(); // again — should be safe
  });

  it("serves success HTML on valid callback", async () => {
    server = new CallbackServer(0);
    const state = "htmltest";

    await server.start(state, 5000);
    const callbackPromise = server.waitForCallback();

    const port = server.listenPort;
    const res = await fetch(`http://127.0.0.1:${port}/oauth/callback?code=ok&state=${state}`);
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(html).toContain("Authorization Successful");

    await callbackPromise;
  });
});

describe("CallbackServer terminal-branch cleanup (code review Low O2)", () => {
  it("clears the timeout and stops the server after a successful callback", async () => {
    const srv = new CallbackServer(0);
    await srv.start("st-ok", 60_000);
    const port = srv.listenPort;

    const res = await fetch(`http://127.0.0.1:${port}/oauth/callback?code=x&state=st-ok`);
    expect(res.status).toBe(200);
    await expect(srv.waitForCallback()).resolves.toMatchObject({ code: "x" });

    // The server closes itself once the response is flushed...
    await new Promise((r) => setTimeout(r, 50));
    expect(srv.isRunning).toBe(false);
    // ...and the 5-minute timer is gone, not merely orphaned.
    expect((srv as unknown as { timeoutId: unknown }).timeoutId).toBeNull();
    await expect(
      fetch(`http://127.0.0.1:${port}/oauth/callback?code=y&state=st-ok`),
    ).rejects.toThrow();
  });

  it("clears the timeout and stops the server after an invalid-state callback", async () => {
    const srv = new CallbackServer(0);
    await srv.start("st-good", 60_000);
    const port = srv.listenPort;
    const pending = srv.waitForCallback();
    // Prevent Node.js from treating this as unhandled
    pending.catch(() => {});

    await fetch(`http://127.0.0.1:${port}/oauth/callback?code=x&state=st-evil`);
    await expect(pending).rejects.toMatchObject({ code: ErrorCode.OAUTH_INVALID_STATE });

    await new Promise((r) => setTimeout(r, 50));
    expect(srv.isRunning).toBe(false);
    expect((srv as unknown as { timeoutId: unknown }).timeoutId).toBeNull();
  });

  it("settles exactly once when a second callback races in", async () => {
    const srv = new CallbackServer(0);
    await srv.start("st-race", 60_000);
    const port = srv.listenPort;

    const first = fetch(`http://127.0.0.1:${port}/oauth/callback?code=one&state=st-race`);
    const second = fetch(`http://127.0.0.1:${port}/oauth/callback?code=two&state=st-race`).catch(
      () => null,
    );
    await Promise.all([first, second]);

    const result = await srv.waitForCallback();
    expect(["one", "two"]).toContain(result.code);
    await srv.stop();
  });
});
