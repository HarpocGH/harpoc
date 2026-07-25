import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { RateLimiter } from "./rate-limit.js";

describe("RateLimiter", () => {
  it("allows requests within the global limit", () => {
    const limiter = new RateLimiter(10, 5, 5);
    for (let i = 0; i < 10; i++) {
      limiter.checkGlobal();
    }
    // 11th should throw
    expect(() => limiter.checkGlobal()).toThrow("Global rate limit exceeded");
  });

  it("allows requests within the per-secret limit", () => {
    const limiter = new RateLimiter(1000, 3, 3);
    for (let i = 0; i < 3; i++) {
      limiter.checkSecret("secret-1");
    }
    expect(() => limiter.checkSecret("secret-1")).toThrow("Per-secret rate limit exceeded");
  });

  it("tracks per-secret limits independently", () => {
    const limiter = new RateLimiter(1000, 2, 2);
    limiter.checkSecret("secret-1");
    limiter.checkSecret("secret-1");
    expect(() => limiter.checkSecret("secret-1")).toThrow();

    // Different secret should still work
    limiter.checkSecret("secret-2");
    limiter.checkSecret("secret-2");
    expect(() => limiter.checkSecret("secret-2")).toThrow();
  });

  it("uses useSecretLimit when isUseSecret is true", () => {
    const limiter = new RateLimiter(1000, 10, 2);
    limiter.checkSecret("secret-1", true);
    limiter.checkSecret("secret-1", true);
    expect(() => limiter.checkSecret("secret-1", true)).toThrow();

    // Regular access still has higher limit
    limiter.checkSecret("secret-2", false);
    limiter.checkSecret("secret-2", false);
    // perSecretLimit is 10, so this should work
    limiter.checkSecret("secret-2", false);
  });

  // L8: the twin of a bug already fixed in mcp-server. The sweep deleted the
  // *in-flight* bucket before `bucket.tokens--`, so past 1000 buckets per-secret
  // limiting silently stopped being enforced — and it tested the stored token
  // count, which never reaches the limit, so the map never actually shrank.
  describe("bucket eviction past the 1000-bucket bound (L8)", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    function buckets(limiter: RateLimiter): Map<string, unknown> {
      return (limiter as unknown as { secretBuckets: Map<string, unknown> }).secretBuckets;
    }

    it("keeps enforcing the per-secret limit for the bucket being checked", () => {
      const limiter = new RateLimiter(1_000_000, 3);
      for (let i = 0; i < 1001; i++) limiter.checkSecret(`s-${i}`);

      // A minute of idleness makes every *other* bucket fully refillable, so
      // the sweep fires on the next access. The in-flight bucket must survive
      // it — deleting it made the decrement land on a discarded object.
      vi.advanceTimersByTime(60_000);
      limiter.checkSecret("victim");
      limiter.checkSecret("victim");
      limiter.checkSecret("victim");
      expect(() => limiter.checkSecret("victim")).toThrow("Per-secret rate limit exceeded");
    });

    it("actually shrinks the map (idle refill is computed, not read)", () => {
      const limiter = new RateLimiter(1_000_000, 5);
      for (let i = 0; i < 1001; i++) limiter.checkSecret(`s-${i}`);
      expect(buckets(limiter).size).toBe(1001);

      vi.advanceTimersByTime(60_000);
      limiter.checkSecret("s-0");
      expect(buckets(limiter).size).toBeLessThanOrEqual(2);
      // An evicted secret simply gets a fresh bucket on its next use.
      expect(() => limiter.checkSecret("s-999")).not.toThrow();
    });

    // Also red under the flip, and instructively so: with the old rule the
    // *newly created* bucket is initialized at the limit, so `refill` swept it
    // out before the caller's decrement — one bucket short and no enforcement.
    it("partially drained buckets survive the sweep", () => {
      const limiter = new RateLimiter(1_000_000, 5);
      for (let i = 0; i < 1001; i++) {
        limiter.checkSecret(`s-${i}`);
        limiter.checkSecret(`s-${i}`);
        limiter.checkSecret(`s-${i}`);
      }
      vi.advanceTimersByTime(12_000); // one refilled token, still short of 5
      limiter.checkSecret("s-0");
      expect(buckets(limiter).size).toBe(1001);
    });

    it("control: below the bound nothing is swept at all", () => {
      const limiter = new RateLimiter(1_000_000, 5);
      for (let i = 0; i < 10; i++) limiter.checkSecret(`s-${i}`);
      vi.advanceTimersByTime(60_000);
      limiter.checkSecret("s-0");
      expect(buckets(limiter).size).toBe(10);
    });
  });
});
