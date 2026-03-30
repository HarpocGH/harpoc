import { afterEach, describe, expect, it, vi } from "vitest";
import { TokenRefreshScheduler } from "./token-refresh.js";

// Mock VaultEngine
function createMockEngine(options?: {
  expiringTokens?: { secret_id: string }[];
  refreshResult?: number | null;
  refreshError?: Error;
}) {
  const refreshCalls: string[] = [];
  let refreshCallCount = 0;

  return {
    engine: {
      getExpiringOAuthTokens: vi.fn().mockReturnValue(options?.expiringTokens ?? []),
      refreshOAuthToken: vi.fn().mockImplementation(async (secretId: string) => {
        refreshCalls.push(secretId);
        refreshCallCount++;
        if (options?.refreshError) throw options.refreshError;
        return options?.refreshResult ?? Date.now() + 3600_000;
      }),
    },
    refreshCalls,
    getRefreshCallCount: () => refreshCallCount,
  };
}

describe("TokenRefreshScheduler", () => {
  let scheduler: TokenRefreshScheduler;

  afterEach(() => {
    scheduler?.stop();
  });

  it("starts and stops without errors", () => {
    const { engine } = createMockEngine();
    scheduler = new TokenRefreshScheduler(engine as never);
    expect(scheduler.isRunning).toBe(false);
    scheduler.start();
    expect(scheduler.isRunning).toBe(true);
    scheduler.stop();
    expect(scheduler.isRunning).toBe(false);
  });

  it("start is idempotent", () => {
    const { engine } = createMockEngine();
    scheduler = new TokenRefreshScheduler(engine as never);
    scheduler.start();
    scheduler.start(); // second call should be no-op
    expect(scheduler.isRunning).toBe(true);
  });

  it("tick refreshes expiring tokens", async () => {
    const { engine, refreshCalls } = createMockEngine({
      expiringTokens: [{ secret_id: "s1" }, { secret_id: "s2" }],
    });

    scheduler = new TokenRefreshScheduler(engine as never, { initialRetryDelayMs: 0 });
    await scheduler.tick();

    expect(engine.getExpiringOAuthTokens).toHaveBeenCalledOnce();
    expect(refreshCalls).toEqual(["s1", "s2"]);
  });

  it("tick continues after individual token refresh failure", async () => {
    let callCount = 0;
    const engine = {
      getExpiringOAuthTokens: vi.fn().mockReturnValue([
        { secret_id: "fail-token" },
        { secret_id: "ok-token" },
      ]),
      refreshOAuthToken: vi.fn().mockImplementation(async (id: string) => {
        callCount++;
        if (id === "fail-token") throw new Error("Refresh failed");
        return Date.now() + 3600_000;
      }),
    };

    scheduler = new TokenRefreshScheduler(engine as never, { initialRetryDelayMs: 0 });
    await scheduler.tick();

    // Both tokens attempted (first fails with retries, second succeeds)
    expect(callCount).toBeGreaterThanOrEqual(2);
  });

  it("refreshNow delegates to engine with retry", async () => {
    const { engine, refreshCalls } = createMockEngine({
      refreshResult: Date.now() + 7200_000,
    });

    scheduler = new TokenRefreshScheduler(engine as never, { initialRetryDelayMs: 0 });
    const result = await scheduler.refreshNow("manual-refresh");

    expect(refreshCalls).toEqual(["manual-refresh"]);
    expect(result).toBeGreaterThan(Date.now());
  });

  it("retries with exponential backoff on failure then succeeds", async () => {
    let callCount = 0;
    const engine = {
      getExpiringOAuthTokens: vi.fn().mockReturnValue([]),
      refreshOAuthToken: vi.fn().mockImplementation(async () => {
        callCount++;
        if (callCount < 3) throw new Error("Transient failure");
        return Date.now() + 3600_000;
      }),
    };

    scheduler = new TokenRefreshScheduler(engine as never, { initialRetryDelayMs: 0 });
    const result = await scheduler.refreshNow("retry-test");

    expect(callCount).toBe(3);
    expect(result).toBeGreaterThan(Date.now());
  });

  it("throws after max retries exhausted", async () => {
    const { engine } = createMockEngine({
      refreshError: new Error("Persistent failure"),
    });

    scheduler = new TokenRefreshScheduler(engine as never, { initialRetryDelayMs: 0 });

    await expect(scheduler.refreshNow("fail-all")).rejects.toThrow("Persistent failure");
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(3);
  });

  it("uses periodic timer when started", async () => {
    vi.useFakeTimers();
    try {
      const { engine } = createMockEngine({
        expiringTokens: [{ secret_id: "periodic-token" }],
      });

      scheduler = new TokenRefreshScheduler(engine as never, { checkIntervalMs: 100 });
      scheduler.start();

      await vi.advanceTimersByTimeAsync(250);

      expect(engine.getExpiringOAuthTokens).toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("stop cancels periodic timer", async () => {
    vi.useFakeTimers();
    try {
      const { engine } = createMockEngine();

      scheduler = new TokenRefreshScheduler(engine as never, { checkIntervalMs: 100 });
      scheduler.start();
      scheduler.stop();

      await vi.advanceTimersByTimeAsync(500);

      expect(engine.getExpiringOAuthTokens).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
