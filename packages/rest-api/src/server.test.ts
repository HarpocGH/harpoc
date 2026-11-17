import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { ErrorCode, VaultError, VaultState } from "@harpoc/shared";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const { bind, createAppSpy, serveSpy } = vi.hoisted(() => {
  const bind = {
    failure: undefined as Error | undefined,
    closes: 0,
    persistent: new Map<string, ((arg?: unknown) => void)[]>(),
  };
  return {
    bind,
    createAppSpy: vi.fn<(engine: unknown, options?: unknown) => { fetch: unknown }>(() => ({
      fetch: vi.fn(),
    })),
    /**
     * `serve` binds asynchronously and reports a failed bind only as an
     * `error` event on the server it has already returned. The fake keeps that
     * contract — one `once` slot per event, an `on` handler kept apart in
     * `bind.persistent`, and a microtask that fires either `listening` or
     * `error` after the caller has registered both — so the order this file
     * pins is the order the real listener imposes.
     */
    serveSpy: vi.fn((options: { port?: number; hostname?: string }) => {
      const handlers = new Map<string, (arg?: unknown) => void>();
      const boundPort = options.port ?? 3000;
      const server = {
        once(event: string, listener: (arg?: unknown) => void) {
          handlers.set(event, listener);
        },
        on(event: string, listener: (arg?: unknown) => void) {
          bind.persistent.set(event, [...(bind.persistent.get(event) ?? []), listener]);
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
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";

function emitListenerError(err: Error): void {
  for (const listener of bind.persistent.get("error") ?? []) listener(err);
}

// ── Tests ──────────────────────────────────────────────────────────

describe("startServer", () => {
  beforeEach(() => {
    bind.failure = undefined;
    bind.closes = 0;
    bind.persistent.clear();
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

  it("a taken port is INVALID_INPUT naming the address and EADDRINUSE, never node's text, details.errno, and writes no start row", async () => {
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;
    bind.failure = Object.assign(new Error("listen EADDRINUSE: address already in use"), {
      code: "EADDRINUSE",
    });

    const err = await expectVaultError(
      () => startServer({ engine, port: 4100 }),
      ErrorCode.INVALID_INPUT,
    );
    expectAbsent(err.message, "address already in use");
    expect(err.message).toBe(
      "REST API: another process is listening on 127.0.0.1:4100 (EADDRINUSE)",
    );
    expect(err.details).toEqual({ errno: "EADDRINUSE" });
    expect(auditServerStart).not.toHaveBeenCalled();
  });

  it("a bind refused EADDRNOTAVAIL on a non-loopback host with an allowed host is INVALID_INPUT naming the address and the errno, never node's text, details.errno, and writes no start row", async () => {
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;
    bind.failure = Object.assign(
      new Error("listen EADDRNOTAVAIL: address not available 192.0.2.1"),
      { code: "EADDRNOTAVAIL", syscall: "listen" },
    );

    const err = await expectVaultError(
      () =>
        startServer({ engine, port: 4100, hostname: "192.0.2.1", allowedHosts: ["vault.example"] }),
      ErrorCode.INVALID_INPUT,
    );
    expectAbsent(err.message, "address not available");
    expect(err.message).toBe("REST API: cannot listen on 192.0.2.1:4100 (EADDRNOTAVAIL)");
    expect(err.details).toEqual({ errno: "EADDRNOTAVAIL" });
    expect(auditServerStart).not.toHaveBeenCalled();
  });

  it("a taken port on ::1 is INVALID_INPUT naming the address bracketed", async () => {
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart: vi.fn() } as never;
    bind.failure = Object.assign(new Error("listen EADDRINUSE: address already in use ::1:4100"), {
      code: "EADDRINUSE",
      syscall: "listen",
    });

    const err = await expectVaultError(
      () => startServer({ engine, port: 4100, hostname: "::1" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe("REST API: another process is listening on [::1]:4100 (EADDRINUSE)");
  });

  it("a bind refused with no errno is INVALID_INPUT naming the address (unknown error), never node's text, no details, and writes no start row", async () => {
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;
    bind.failure = new Error("listen failed");

    const err = await expectVaultError(
      () => startServer({ engine, port: 4100 }),
      ErrorCode.INVALID_INPUT,
    );
    expectAbsent(err.message, "listen failed");
    expect(err.message).toBe("REST API: cannot listen on 127.0.0.1:4100 (unknown error)");
    expect(err.details).toBeUndefined();
    expect(auditServerStart).not.toHaveBeenCalled();
  });

  it("an accept error after the bind is handed to onListenerError once, INTERNAL_ERROR naming the address the bind reported and the errno, never node's text, details.errno", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart: vi.fn() } as never;
    const onListenerError = vi.fn<(err: VaultError) => void>();

    const started = startServer({ engine, port: 0, onListenerError });
    const server = serveSpy.mock.results[0]?.value as { address: () => unknown };
    server.address = () => ({ address: "127.0.0.1", family: "IPv4", port: 4100 });
    await started;
    emitListenerError(
      Object.assign(new Error("accept ENOBUFS"), { code: "ENOBUFS", syscall: "accept" }),
    );

    expect(onListenerError).toHaveBeenCalledTimes(1);
    const err = onListenerError.mock.calls[0]?.[0] as VaultError;
    expectAbsent(err.message, "accept ");
    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.message).toBe("REST API: the listener on 127.0.0.1:4100 failed (ENOBUFS)");
    expect(err.details).toEqual({ errno: "ENOBUFS" });
  });

  it("a listener error without a code is handed to onListenerError once, INTERNAL_ERROR naming the address (unknown error), never node's text, no details", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart: vi.fn() } as never;
    const onListenerError = vi.fn<(err: VaultError) => void>();

    await startServer({ engine, port: 4100, onListenerError });
    emitListenerError(new Error("accept failed"));

    expect(onListenerError).toHaveBeenCalledTimes(1);
    const err = onListenerError.mock.calls[0]?.[0] as VaultError;
    expectAbsent(err.message, "accept failed");
    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.message).toBe("REST API: the listener on 127.0.0.1:4100 failed (unknown error)");
    expect(err.details).toBeUndefined();
  });

  it("with the bound server's address() throwing after the bind, a listener error's call throws nothing and onListenerError receives once the message naming the address taken at the bind", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart: vi.fn() } as never;
    const onListenerError = vi.fn<(err: VaultError) => void>();

    const server = await startServer({ engine, port: 4100, onListenerError });
    server.address = () => {
      throw Object.assign(new Error("getsockname EBADF"), {
        code: "EBADF",
        syscall: "getsockname",
      });
    };

    expect(() =>
      emitListenerError(
        Object.assign(new Error("accept ENOBUFS"), { code: "ENOBUFS", syscall: "accept" }),
      ),
    ).not.toThrow();
    expect(onListenerError).toHaveBeenCalledTimes(1);
    expect((onListenerError.mock.calls[0]?.[0] as VaultError).message).toBe(
      "REST API: the listener on 127.0.0.1:4100 failed (ENOBUFS)",
    );
  });

  it("without onListenerError exactly one persistent error handler is stored and a listener error's call throws nothing", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart: vi.fn() } as never;

    await startServer({ engine, port: 4100 });

    expect(bind.persistent.get("error")).toHaveLength(1);
    expect(() =>
      emitListenerError(
        Object.assign(new Error("accept ENOBUFS"), { code: "ENOBUFS", syscall: "accept" }),
      ),
    ).not.toThrow();
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

  it.each([
    [70000, "70000"],
    [-1, "-1"],
    [1.5, "1.5"],
    [Number.NaN, "NaN"],
  ] as const)(
    "port %s is INVALID_INPUT naming the port, before the app is built, nothing served and no start row",
    async (port, printed) => {
      const auditServerStart = vi.fn();
      const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;

      const err = await expectVaultError(
        () => startServer({ engine, port }),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(`REST API: port ${printed} is not 0-65535`);
      expect(createAppSpy).not.toHaveBeenCalled();
      expect(serveSpy).not.toHaveBeenCalled();
      expect(auditServerStart).not.toHaveBeenCalled();
    },
  );

  it("ports 0 and 65535 pass the port check: each is served and writes its start row with that port", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart } as never;

    await startServer({ engine, port: 0 });
    await startServer({ engine, port: 65535 });

    expect(serveSpy).toHaveBeenCalledTimes(2);
    expect(auditServerStart).toHaveBeenNthCalledWith(1, {
      transport: "rest",
      tokenless: false,
      port: 0,
      host: "127.0.0.1",
    });
    expect(auditServerStart).toHaveBeenNthCalledWith(2, {
      transport: "rest",
      tokenless: false,
      port: 65535,
      host: "127.0.0.1",
    });
  });
});
