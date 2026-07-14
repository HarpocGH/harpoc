import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { RateLimiter } from "./rate-limiter.js";

describe("RateLimiter", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("allows requests within global limit", () => {
    const limiter = new RateLimiter(5);
    for (let i = 0; i < 5; i++) {
      expect(() => limiter.checkLimit()).not.toThrow();
    }
  });

  it("rejects when global limit exceeded", () => {
    const limiter = new RateLimiter(3);
    limiter.checkLimit();
    limiter.checkLimit();
    limiter.checkLimit();
    expect(() => limiter.checkLimit()).toThrow(
      expect.objectContaining({ code: ErrorCode.RATE_LIMIT_EXCEEDED }),
    );
  });

  it("allows requests within per-secret limit", () => {
    const limiter = new RateLimiter(1000, 3);
    for (let i = 0; i < 3; i++) {
      expect(() => limiter.checkLimit("secret-1")).not.toThrow();
    }
  });

  it("rejects when per-secret limit exceeded", () => {
    const limiter = new RateLimiter(1000, 2);
    limiter.checkLimit("secret-1");
    limiter.checkLimit("secret-1");
    expect(() => limiter.checkLimit("secret-1")).toThrow(
      expect.objectContaining({ code: ErrorCode.RATE_LIMIT_EXCEEDED }),
    );
  });

  it("use_secret has elevated per-secret limit", () => {
    const limiter = new RateLimiter(1000, 2, 5);
    // Non-use_secret: limit is 2
    limiter.checkLimit("secret-1", false);
    limiter.checkLimit("secret-1", false);
    expect(() => limiter.checkLimit("secret-1", false)).toThrow();

    // use_secret for different secret: limit is 5
    for (let i = 0; i < 5; i++) {
      expect(() => limiter.checkLimit("secret-2", true)).not.toThrow();
    }
    expect(() => limiter.checkLimit("secret-2", true)).toThrow();
  });

  it("different secrets have independent buckets", () => {
    const limiter = new RateLimiter(1000, 2);
    limiter.checkLimit("secret-a");
    limiter.checkLimit("secret-a");
    expect(() => limiter.checkLimit("secret-a")).toThrow();

    // secret-b should still work
    expect(() => limiter.checkLimit("secret-b")).not.toThrow();
  });

  it("refills tokens after time passes", () => {
    const limiter = new RateLimiter(10);
    // Exhaust all tokens
    for (let i = 0; i < 10; i++) {
      limiter.checkLimit();
    }
    expect(() => limiter.checkLimit()).toThrow();

    // Advance time by 1 minute — should fully refill
    vi.advanceTimersByTime(60_000);
    expect(() => limiter.checkLimit()).not.toThrow();
  });

  it("partial refill after partial time", () => {
    const limiter = new RateLimiter(10);
    for (let i = 0; i < 10; i++) {
      limiter.checkLimit();
    }
    expect(() => limiter.checkLimit()).toThrow();

    // Advance time by 30 seconds — should refill 5 tokens (50% of a minute)
    vi.advanceTimersByTime(30_000);
    for (let i = 0; i < 5; i++) {
      expect(() => limiter.checkLimit()).not.toThrow();
    }
    expect(() => limiter.checkLimit()).toThrow();
  });

  it("evicts idle fully-refillable secret buckets past the 1000-bucket bound", () => {
    const limiter = new RateLimiter(1_000_000, 5);
    for (let i = 0; i < 1001; i++) {
      limiter.checkLimit(`s-${i}`);
    }
    const buckets = (limiter as unknown as { secretBuckets: Map<string, unknown> }).secretBuckets;
    expect(buckets.size).toBe(1001);

    // A minute of idleness makes every bucket fully refillable; the next
    // access past the bound sweeps them out instead of growing forever.
    vi.advanceTimersByTime(60_000);
    limiter.checkLimit("s-0");
    expect(buckets.size).toBeLessThanOrEqual(2);

    // Evicted secrets simply get fresh buckets on their next use.
    expect(() => limiter.checkLimit("s-999")).not.toThrow();
  });

  it("does not evict buckets that are still partially drained", () => {
    const limiter = new RateLimiter(1_000_000, 5);
    for (let i = 0; i < 1001; i++) {
      limiter.checkLimit(`s-${i}`);
      limiter.checkLimit(`s-${i}`);
      limiter.checkLimit(`s-${i}`);
    }
    // Only ~12s of idleness: one refilled token, still below the limit.
    vi.advanceTimersByTime(12_000);
    const buckets = (limiter as unknown as { secretBuckets: Map<string, unknown> }).secretBuckets;
    limiter.checkLimit("s-0");
    expect(buckets.size).toBe(1001);
  });
});
