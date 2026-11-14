import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ErrorCode, VaultError } from "./errors.js";
import { RateLimiter } from "./rate-limiter.js";

/** The limiter's private bucket map, read through the cast the L8 rows use. */
function bucketsOf(limiter: RateLimiter): Map<string, unknown> {
  return (limiter as unknown as { secretBuckets: Map<string, unknown> }).secretBuckets;
}

describe("RateLimiter eviction sweep past the 1 000-bucket bound", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("a use-rate key drawn through checkLimit keeps its own budget", () => {
    const limiter = new RateLimiter(1_000_000, 5, 10);
    for (let i = 0; i < 1001; i++) {
      for (let n = 0; n < 5; n++) limiter.checkSecret(`s-${i}`);
    }

    for (let n = 0; n < 10; n++) {
      expect(() => limiter.checkLimit("v", true)).not.toThrow();
    }
    let thrown: unknown;
    try {
      limiter.checkLimit("v", true);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect(thrown).toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      message: "Per-secret rate limit exceeded",
    });
  });

  it("two use-rate keys drawn in turn do not evict each other at the default limits", () => {
    const limiter = new RateLimiter();
    for (let i = 0; i < 1001; i++) {
      for (let n = 0; n < 61; n++) limiter.checkSecret(`u-${i}`, true);
    }

    const pair = (): void => {
      limiter.checkSecret("sign:c", true);
      limiter.checkSecret("key", true);
    };
    for (let n = 0; n < 120; n++) {
      expect(pair).not.toThrow();
    }
    let thrown: unknown;
    try {
      pair();
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(VaultError);
    expect(thrown).toMatchObject({
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      message: "Per-secret rate limit exceeded",
    });
  });

  it("keeps a use-rate bucket its own refill has not yet filled", () => {
    const limiter = new RateLimiter(1_000_000, 5, 10);
    for (let i = 0; i < 1001; i++) limiter.checkSecret(`s-${i}`);
    limiter.checkSecret("v", true);

    vi.advanceTimersByTime(1_000);
    limiter.checkSecret("s-0");
    expect(bucketsOf(limiter).has("v")).toBe(true);
  });

  it("evicts a use-rate bucket once its own window has refilled it", () => {
    const limiter = new RateLimiter(1_000_000, 5, 10);
    for (let i = 0; i < 1001; i++) limiter.checkSecret(`s-${i}`);
    limiter.checkSecret("v", true);

    vi.advanceTimersByTime(6_000);
    limiter.checkSecret("s-0");
    expect(bucketsOf(limiter).has("v")).toBe(false);
  });
});
