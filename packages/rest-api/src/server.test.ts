import { describe, it, expect, vi, afterEach } from "vitest";
import { VaultState } from "@harpoc/shared";

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
    const engine = { getState: () => VaultState.UNLOCKED } as never;
    const oauthManager = { cancelPendingFlows: vi.fn() } as never;

    startServer({ engine, oauthManager });

    expect(createAppSpy).toHaveBeenCalledTimes(1);
    const [, options] = createAppSpy.mock.calls[0] ?? [];
    expect((options as { oauthManager?: unknown } | undefined)?.oauthManager).toBe(oauthManager);
  });
});
