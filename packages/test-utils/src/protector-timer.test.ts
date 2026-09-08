import { describe, expect, it } from "vitest";
import { protectorTimer } from "./protector-timer.js";

/** A protector whose protect reverses the bytes and whose unprotect reverses them back. */
const reversing = (scheme: string) => ({
  scheme,
  protect: (key: Uint8Array) => Promise.resolve(Uint8Array.from(key).reverse()),
  unprotect: (blob: Uint8Array) => Promise.resolve(Uint8Array.from(blob).reverse()),
});

describe("protectorTimer (D3, 2026-09-08)", () => {
  it("delegates both calls, keeps the scheme, and reports them in order with (ok)", async () => {
    const timer = protectorTimer("t");
    const timed = timer.wrap(reversing("fake"));
    const key = Uint8Array.from([1, 2, 3]);
    expect(timed.scheme).toBe("fake");
    const blob = await timed.protect(key);
    expect(Array.from(blob)).toEqual([3, 2, 1]);
    expect(Array.from(await timed.unprotect(blob))).toEqual([1, 2, 3]);
    expect(timer.report()).toMatch(/^\[t\] protect=\d+ms \(ok\), unprotect=\d+ms \(ok\)$/);
  });

  it("records a failed call with its message and rethrows it", async () => {
    const timer = protectorTimer("t");
    const timed = timer.wrap({
      ...reversing("fake"),
      protect: () => Promise.reject(new Error("DPAPI Protect timed out after 1ms")),
    });
    await expect(timed.protect(Uint8Array.from([7]))).rejects.toThrow("timed out after 1ms");
    expect(timer.report()).toMatch(/^\[t\] protect=\d+ms \(DPAPI Protect timed out after 1ms\)$/);
  });

  it("aggregates every wrapped instance into one line, in call order", async () => {
    const timer = protectorTimer("t");
    const a = timer.wrap(reversing("fake"));
    const b = timer.wrap(reversing("fake"));
    const blob = await a.protect(Uint8Array.from([9]));
    await b.unprotect(blob);
    expect(timer.report()).toMatch(/^\[t\] protect=\d+ms \(ok\), unprotect=\d+ms \(ok\)$/);
  });

  it("reports no calls before any call", () => {
    expect(protectorTimer("t").report()).toBe("[t] no calls");
  });

  it("stringifies a non-Error rejection and rethrows it", async () => {
    const timer = protectorTimer("t");
    const timed = timer.wrap({ ...reversing("fake"), unprotect: () => Promise.reject("boom") });
    await expect(timed.unprotect(Uint8Array.from([1]))).rejects.toBe("boom");
    expect(timer.report()).toMatch(/^\[t\] unprotect=\d+ms \(boom\)$/);
  });

  it("slowestMs is 0 before any call", () => {
    expect(protectorTimer("t").slowestMs()).toBe(0);
  });

  it("slowestMs is the slowest call so far, a failed call included", async () => {
    const timer = protectorTimer("t");
    const slow = timer.wrap({
      ...reversing("fake"),
      protect: () =>
        new Promise<Uint8Array>((resolve) => setTimeout(() => resolve(Uint8Array.from([1])), 30)),
      unprotect: () =>
        new Promise<Uint8Array>((_, reject) =>
          setTimeout(() => reject(new Error("slow fail")), 60),
        ),
    });
    await slow.protect(Uint8Array.from([1]));
    const afterProtect = timer.slowestMs();
    expect(afterProtect).toBeGreaterThanOrEqual(25);
    await expect(slow.unprotect(Uint8Array.from([1]))).rejects.toThrow("slow fail");
    expect(timer.slowestMs()).toBeGreaterThanOrEqual(55);
    expect(timer.slowestMs()).toBeGreaterThanOrEqual(afterProtect);
  });
});
