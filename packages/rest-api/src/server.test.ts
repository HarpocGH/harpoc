import { describe, it, expect, vi, afterEach } from "vitest";
import { ErrorCode, VaultState } from "@harpoc/shared";

// ── Hoisted mocks (available inside vi.mock factories) ─────────────

const { createAppSpy, serveSpy } = vi.hoisted(() => ({
  createAppSpy: vi.fn<(engine: unknown, options?: unknown) => { fetch: unknown }>(() => ({
    fetch: vi.fn(),
  })),
  serveSpy: vi.fn<(options: unknown) => { close: unknown }>(() => ({ close: vi.fn() })),
}));

// ── Module mocks ───────────────────────────────────────────────────

vi.mock("./app.js", () => ({ createApp: createAppSpy }));
vi.mock("@hono/node-server", () => ({ serve: serveSpy }));

import { startServer } from "./server.js";

// ── Tests ──────────────────────────────────────────────────────────

describe("startServer", () => {
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
  it("forwards the caller's oauthManager into createApp (shutdown owns its flows)", () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = { getState: () => VaultState.UNLOCKED, auditServerStart: vi.fn() } as never;
    const oauthManager = { cancelPendingFlows: vi.fn() } as never;

    startServer({ engine, oauthManager });

    expect(createAppSpy).toHaveBeenCalledTimes(1);
    const [, options] = createAppSpy.mock.calls[0] ?? [];
    expect((options as { oauthManager?: unknown } | undefined)?.oauthManager).toBe(oauthManager);
  });

  it("writes the rest listener's server.start row before serving (R4/B22)", () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const auditServerStart = vi.fn();
    const engine = {
      getState: () => VaultState.UNLOCKED,
      auditServerStart,
    } as never;

    startServer({ engine, port: 4100, hostname: "127.0.0.1" });

    expect(auditServerStart).toHaveBeenCalledTimes(1);
    expect(auditServerStart).toHaveBeenCalledWith({
      transport: "rest",
      tokenless: false,
      port: 4100,
      host: "127.0.0.1",
    });
    const rowOrder = auditServerStart.mock.invocationCallOrder[0] as number;
    const serveOrder = serveSpy.mock.invocationCallOrder[0] as number;
    expect(rowOrder).toBeLessThan(serveOrder);
  });

  it("a sealed engine refuses before the app is built (D1)", () => {
    const auditServerStart = vi.fn();
    const engine = { getState: () => VaultState.SEALED, auditServerStart } as never;

    expect(() => startServer({ engine })).toThrow(
      expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
    );
    expect(createAppSpy).not.toHaveBeenCalled();
    expect(auditServerStart).not.toHaveBeenCalled();
    expect(serveSpy).not.toHaveBeenCalled();
  });

  it("fails closed: an unwritable row means no listener", () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const engine = {
      getState: () => VaultState.UNLOCKED,
      auditServerStart: vi.fn().mockImplementation(() => {
        throw new Error("audit log unwritable");
      }),
    } as never;

    expect(() => startServer({ engine })).toThrow("audit log unwritable");
    expect(serveSpy).not.toHaveBeenCalled();
  });
});
