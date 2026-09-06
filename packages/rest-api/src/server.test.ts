import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { ErrorCode, VaultError, VaultState } from "@harpoc/shared";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const { bind, createAppSpy, serveSpy } = vi.hoisted(() => {
  const bind = { failure: undefined as Error | undefined, closes: 0 };
  return {
    bind,
    createAppSpy: vi.fn<(engine: unknown, options?: unknown) => { fetch: unknown }>(() => ({
      fetch: vi.fn(),
    })),
    /**
     * `serve` binds asynchronously and reports a failed bind only as an
     * `error` event on the server it has already returned. The fake keeps that
     * contract — one handler slot per event, and a microtask that fires either
     * `listening` or `error` after the caller has registered both — so the
     * order this file pins is the order the real listener imposes.
     */
    serveSpy: vi.fn((options: { port?: number; hostname?: string }) => {
      const handlers = new Map<string, (arg?: unknown) => void>();
      const boundPort = options.port ?? 3000;
      const server = {
        once(event: string, listener: (arg?: unknown) => void) {
          handlers.set(event, listener);
        },
        removeListener(event: string) {
          handlers.delete(event);
        },
        address() {
          return { address: options.hostname ?? "127.0.0.1", family: "IPv4", port: boundPort };
        },
        close(callback?: () => void) {
          bind.closes += 1;
          if (callback) callback();
        },
      };
      queueMicrotask(() => {
        if (bind.failure !== undefined) handlers.get("error")?.(bind.failure);
        else handlers.get("listening")?.();
      });
      return server;
    }),
  };
});

// ── Module mocks ───────────────────────────────────────────────────

vi.mock("./app.js", () => ({ createApp: createAppSpy }));
vi.mock("@hono/node-server", () => ({ serve: serveSpy }));

import { startServer } from "./server.js";

// ── Tests ──────────────────────────────────────────────────────────

describe("startServer", () => {
  beforeEach(() => {
    bind.failure = undefined;
    bind.closes = 0;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    createAppSpy.mockClear();
    serveSpy.mockClear();
  });

  /**
   * The process that owns the server constructs the OAuth manager so it can
   * cancel its pending background flows on shutdown; a manager `createApp`
   * builds for itself has no dispose path. `startServer` therefore has to hand
   * the caller's options through — dropping them would silently give the app a
   * second manager, and shutdown would cancel flows nobody is running.
   */
  it("forwards the caller's oauthManager into createApp (shutdown owns its flows)", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart: vi.fn() } as never;
    const oauthManager = { cancelPendingFlows: vi.fn() } as never;

    await startServer({ engine, oauthManager });

    expect(createAppSpy).toHaveBeenCalledTimes(1);
    const [, options] = createAppSpy.mock.calls[0] ?? [];
    expect((options as { oauthManager?: unknown } | undefined)?.oauthManager).toBe(oauthManager);
  });

  /**
   * Inverted 2026-09-06 (R26/D9). The row is the record that a listener came
   * up: written before the bind it recorded listeners that never existed, and
   * the port it carried was the requested one rather than the bound one.
   */
  it("writes the rest listener's server.start row after the bind, with the bound port", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;

    await startServer({ engine, port: 4100, hostname: "127.0.0.1" });

    expect(auditServerStart).toHaveBeenCalledTimes(1);
    expect(auditServerStart).toHaveBeenCalledWith({
      transport: "rest",
      tokenless: false,
      port: 4100,
      host: "127.0.0.1",
    });
    const rowOrder = auditServerStart.mock.invocationCallOrder[0] as number;
    const serveOrder = serveSpy.mock.invocationCallOrder[0] as number;
    expect(serveOrder).toBeLessThan(rowOrder);
  });

  it("a failing bind rejects and writes no start row", async () => {
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;
    bind.failure = Object.assign(new Error("listen EADDRINUSE: address already in use"), {
      code: "EADDRINUSE",
    });

    await expect(startServer({ engine, port: 4100 })).rejects.toThrow("EADDRINUSE");
    expect(auditServerStart).not.toHaveBeenCalled();
  });

  it("an unwritable row closes the listener and rethrows", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = {
      getState: () => VaultState.UNLOCKED,
      auditServerStart: vi.fn().mockImplementation(() => {
        throw new Error("audit log unwritable");
      }),
    } as never;

    await expect(startServer({ engine })).rejects.toThrow("audit log unwritable");
    expect(serveSpy).toHaveBeenCalledTimes(1);
    expect(bind.closes).toBe(1);
  });

  it("D61: refuses a non-loopback bind without an allowed host before the app is built", async () => {
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;

    const thrown = await startServer({ engine, hostname: "0.0.0.0" }).catch((err: unknown) => err);

    expect(thrown).toBeInstanceOf(VaultError);
    expect((thrown as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
    expect(createAppSpy).not.toHaveBeenCalled();
    expect(serveSpy).not.toHaveBeenCalled();
    expect(auditServerStart).not.toHaveBeenCalled();
  });

  it("D61: hands the listener's allowed-host set to createApp and no longer warns", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const engine = {
      getState: () => VaultState.UNLOCKED,
      auditServerStart: vi.fn(),
    } as never;

    await startServer({ engine, hostname: "0.0.0.0", allowedHosts: ["Vault.Example"] });
    const [, nonLoopback] = createAppSpy.mock.calls[0] ?? [];
    expect(
      [...(nonLoopback as { allowedHostSet: ReadonlySet<string> }).allowedHostSet].sort(),
    ).toEqual(["vault.example"]);
    expect(warn).not.toHaveBeenCalled();

    createAppSpy.mockClear();
    await startServer({ engine, hostname: "127.0.0.1" });
    const [, loopback] = createAppSpy.mock.calls[0] ?? [];
    expect(
      [...(loopback as { allowedHostSet: ReadonlySet<string> }).allowedHostSet].sort(),
    ).toEqual(["127.0.0.1", "::1", "localhost"]);
  });

  it("a sealed engine refuses before the app is built (D1)", async () => {
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.SEALED, auditServerStart } as never;

    await expect(startServer({ engine })).rejects.toThrow(
      expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
    );
    expect(createAppSpy).not.toHaveBeenCalled();
    expect(auditServerStart).not.toHaveBeenCalled();
    expect(serveSpy).not.toHaveBeenCalled();
  });
});
