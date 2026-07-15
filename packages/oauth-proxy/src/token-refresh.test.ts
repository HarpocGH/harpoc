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

  it("skips interval firings while a previous tick is still running", async () => {
    vi.useFakeTimers();
    try {
      let release: () => void = () => {};
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const engine = {
        getExpiringOAuthTokens: vi.fn().mockReturnValue([{ secret_id: "slow-token" }]),
        refreshOAuthToken: vi.fn().mockImplementation(async () => {
          await gate;
          return Date.now() + 3600_000;
        }),
      };

      scheduler = new TokenRefreshScheduler(engine as never, {
        checkIntervalMs: 100,
        initialRetryDelayMs: 0,
      });
      scheduler.start();

      // Three interval firings while the first tick is blocked on the slow refresh
      await vi.advanceTimersByTimeAsync(350);
      expect(engine.getExpiringOAuthTokens).toHaveBeenCalledTimes(1);
      expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(1);

      release();
      await vi.advanceTimersByTimeAsync(0);

      // Once the slow tick settles, the next firing runs a fresh tick
      await vi.advanceTimersByTimeAsync(100);
      expect(engine.getExpiringOAuthTokens).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("TokenRefreshScheduler onRefreshError", () => {
  let scheduler: TokenRefreshScheduler;

  afterEach(() => {
    scheduler?.stop();
    vi.useRealTimers();
  });

  it("invokes onRefreshError with secretId and error after retries are exhausted", async () => {
    const refreshError = new Error("provider offline");
    const { engine } = createMockEngine({
      expiringTokens: [{ secret_id: "broken" }],
      refreshError,
    });
    const reported: { secretId: string; err: unknown }[] = [];

    scheduler = new TokenRefreshScheduler(engine as never, {
      initialRetryDelayMs: 0,
      onRefreshError: (secretId, err) => {
        reported.push({ secretId, err });
      },
    });
    await scheduler.tick();

    expect(reported).toEqual([{ secretId: "broken", err: refreshError }]);
  });

  it("does not invoke onRefreshError on successful refresh", async () => {
    const { engine } = createMockEngine({
      expiringTokens: [{ secret_id: "healthy" }],
    });
    const onRefreshError = vi.fn();

    scheduler = new TokenRefreshScheduler(engine as never, {
      initialRetryDelayMs: 0,
      onRefreshError,
    });
    await scheduler.tick();

    expect(engine.refreshOAuthToken).toHaveBeenCalledOnce();
    expect(onRefreshError).not.toHaveBeenCalled();
  });

  it("does not re-invoke onRefreshError for a token skipped by quarantine", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(1_700_000_000_000);

    const { engine } = createMockEngine({
      expiringTokens: [{ secret_id: "broken" }],
      refreshError: new Error("dead"),
    });
    const onRefreshError = vi.fn();

    scheduler = new TokenRefreshScheduler(engine as never, {
      checkIntervalMs: 1000,
      initialRetryDelayMs: 0,
      onRefreshError,
    });

    await scheduler.tick(); // fails after retries → reported once, quarantined
    await scheduler.tick(); // inside the window → skipped, no second report
    expect(onRefreshError).toHaveBeenCalledTimes(1);
  });

  it("refreshNow rethrows to the caller without invoking onRefreshError", async () => {
    const { engine } = createMockEngine({ refreshError: new Error("still dead") });
    const onRefreshError = vi.fn();

    scheduler = new TokenRefreshScheduler(engine as never, {
      initialRetryDelayMs: 0,
      onRefreshError,
    });

    await expect(scheduler.refreshNow("manual")).rejects.toThrow("still dead");
    expect(onRefreshError).not.toHaveBeenCalled();
  });
});

describe("TokenRefreshScheduler failure quarantine (code review Low O4)", () => {
  let scheduler: TokenRefreshScheduler;

  afterEach(() => {
    scheduler?.stop();
    vi.useRealTimers();
  });

  function failingEngine() {
    return {
      getExpiringOAuthTokens: vi.fn().mockReturnValue([{ secret_id: "broken" }]),
      refreshOAuthToken: vi.fn().mockRejectedValue(new Error("provider offline")),
    };
  }

  it("skips a failed token until its backoff window elapses, then retries with doubled backoff", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const base = 1_700_000_000_000;
    vi.setSystemTime(base);

    const engine = failingEngine();
    scheduler = new TokenRefreshScheduler(engine as never, {
      checkIntervalMs: 1000,
      initialRetryDelayMs: 0,
    });

    await scheduler.tick(); // 3 in-call attempts, then quarantined for 1000*2^1 = 2s
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(3);

    await scheduler.tick(); // still inside the window: skipped entirely
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(3);

    vi.setSystemTime(base + 2001); // past the first backoff
    await scheduler.tick(); // retried: 3 more attempts, backoff now 4s
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(6);

    vi.setSystemTime(base + 2001 + 3000); // inside the 4s window
    await scheduler.tick();
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(6);

    vi.setSystemTime(base + 2001 + 4001); // past it
    await scheduler.tick();
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(9);
  });

  it("a successful refresh clears the quarantine", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const base = 1_700_000_000_000;
    vi.setSystemTime(base);

    let fail = true;
    const engine = {
      getExpiringOAuthTokens: vi.fn().mockReturnValue([{ secret_id: "flaky" }]),
      refreshOAuthToken: vi.fn().mockImplementation(async () => {
        if (fail) throw new Error("transient");
        return Date.now() + 3600_000;
      }),
    };
    scheduler = new TokenRefreshScheduler(engine as never, {
      checkIntervalMs: 1000,
      initialRetryDelayMs: 0,
    });

    await scheduler.tick(); // quarantined
    fail = false;
    vi.setSystemTime(base + 2001);
    await scheduler.tick(); // succeeds, quarantine cleared
    const after = engine.refreshOAuthToken.mock.calls.length;

    await scheduler.tick(); // no window: refreshed again immediately
    expect(engine.refreshOAuthToken.mock.calls.length).toBe(after + 1);
  });

  it("refreshNow bypasses the quarantine (explicit operator action)", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(1_700_000_000_000);

    const engine = failingEngine();
    scheduler = new TokenRefreshScheduler(engine as never, {
      checkIntervalMs: 1000,
      initialRetryDelayMs: 0,
    });

    await scheduler.tick(); // quarantined
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(3);

    await expect(scheduler.refreshNow("broken")).rejects.toThrow("provider offline");
    expect(engine.refreshOAuthToken).toHaveBeenCalledTimes(6);
  });

  it("one quarantined token does not block others", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(1_700_000_000_000);

    const engine = {
      getExpiringOAuthTokens: vi
        .fn()
        .mockReturnValue([{ secret_id: "broken" }, { secret_id: "healthy" }]),
      refreshOAuthToken: vi.fn().mockImplementation(async (id: string) => {
        if (id === "broken") throw new Error("dead");
        return Date.now() + 3600_000;
      }),
    };
    scheduler = new TokenRefreshScheduler(engine as never, {
      checkIntervalMs: 1000,
      initialRetryDelayMs: 0,
    });

    await scheduler.tick(); // broken: 3 attempts + quarantine; healthy: 1
    await scheduler.tick(); // broken skipped; healthy again
    const healthyCalls = engine.refreshOAuthToken.mock.calls.filter((c) => c[0] === "healthy");
    const brokenCalls = engine.refreshOAuthToken.mock.calls.filter((c) => c[0] === "broken");
    expect(healthyCalls.length).toBe(2);
    expect(brokenCalls.length).toBe(3);
  });
});
