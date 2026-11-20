import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RATE_LIMIT_PROXY_REFUSALS, RATE_LIMIT_PROXY_REFUSAL_WINDOW_MS } from "@harpoc/shared";
import { RefusalBudget, refusalBudgetKey } from "./refusal-budget.js";

const KEY = "agent:a";
let clock = 0;

function budget(): RefusalBudget {
  return new RefusalBudget(3, 60_000, () => clock);
}

function trip(subject: RefusalBudget, key = KEY): boolean[] {
  return [subject.charge(key), subject.charge(key), subject.charge(key)];
}

beforeEach(() => {
  clock = 0;
});

afterEach(() => {
  vi.useRealTimers();
});

describe("RefusalBudget — a fixed window from a principal's first charge (B1)", () => {
  it("below the limit a key is not spent and no charge reports a trip", () => {
    const subject = budget();
    expect(subject.spent(KEY)).toBe(false);
    expect([subject.charge(KEY), subject.charge(KEY)]).toEqual([false, false]);
    expect(subject.spent(KEY)).toBe(false);
  });

  it("the charge that reaches the limit reports the trip, once", () => {
    const subject = budget();
    expect([...trip(subject), subject.charge(KEY)]).toEqual([false, false, true, false]);
    expect(subject.spent(KEY)).toBe(true);
  });

  it("a spent key stays spent until its window ends, counted from its first charge", () => {
    const subject = budget();
    subject.charge(KEY);
    clock = 30_000;
    expect([subject.charge(KEY), subject.charge(KEY)]).toEqual([false, true]);
    clock = 59_999;
    expect(subject.spent(KEY)).toBe(true);
    clock = 60_000;
    expect(subject.spent(KEY)).toBe(false);
  });

  it("a charge on a spent key does not extend the window", () => {
    const subject = budget();
    expect(trip(subject)).toEqual([false, false, true]);
    clock = 59_999;
    expect(subject.charge(KEY)).toBe(false);
    clock = 60_000;
    expect(subject.spent(KEY)).toBe(false);
  });

  it("keys are independent", () => {
    const subject = budget();
    expect(trip(subject)).toEqual([false, false, true]);
    expect(subject.spent("agent:b")).toBe(false);
    expect(trip(subject, "agent:b")).toEqual([false, false, true]);
    expect([subject.spent(KEY), subject.spent("agent:b")]).toEqual([true, true]);
  });

  it("after the window the count starts again", () => {
    const subject = budget();
    expect(trip(subject)).toEqual([false, false, true]);
    clock = 60_000;
    expect(trip(subject)).toEqual([false, false, true]);
    expect(subject.spent(KEY)).toBe(true);
  });

  it("the key holds the principal's type and id", () => {
    const agent = refusalBudgetKey({ principal_type: "agent", principal_id: "a" });
    const tool = refusalBudgetKey({ principal_type: "tool", principal_id: "a" });
    expect(agent).toBe("agent:a");
    expect(tool).toBe("tool:a");
  });

  it("the defaults are the shared constants", () => {
    vi.useFakeTimers({ now: new Date("2026-11-18T12:00:00Z") });
    const subject = new RefusalBudget();
    const charges = Array.from({ length: RATE_LIMIT_PROXY_REFUSALS }, () => subject.charge(KEY));
    expect(charges.indexOf(true)).toBe(RATE_LIMIT_PROXY_REFUSALS - 1);
    vi.advanceTimersByTime(RATE_LIMIT_PROXY_REFUSAL_WINDOW_MS - 1);
    expect(subject.spent(KEY)).toBe(true);
    vi.advanceTimersByTime(1);
    expect(subject.spent(KEY)).toBe(false);
  });

  it("the package entry exports the class the proxy's refusalBudget option takes", async () => {
    const entry = await import("./index.js");
    expect(entry.RefusalBudget).toBe(RefusalBudget);
  });
});

describe("RefusalBudget — the refused authorities a window remembers", () => {
  const EVIL = "evil.example:443";

  it("an authority is not refused before it is remembered", () => {
    const subject = budget();
    expect(subject.refused(KEY, EVIL)).toBe(false);
    subject.charge(KEY);
    expect(subject.refused(KEY, EVIL)).toBe(false);
  });

  it("a remembered authority is refused, another port of its host is not", () => {
    const subject = budget();
    subject.charge(KEY);
    subject.remember(KEY, EVIL);
    expect(subject.refused(KEY, EVIL)).toBe(true);
    expect(subject.refused(KEY, "evil.example:8443")).toBe(false);
  });

  it("a remembered authority is forgotten when the window ends", () => {
    const subject = budget();
    subject.charge(KEY);
    subject.remember(KEY, EVIL);
    clock = 59_999;
    expect(subject.refused(KEY, EVIL)).toBe(true);
    clock = 60_000;
    expect(subject.refused(KEY, EVIL)).toBe(false);
    subject.charge(KEY);
    expect(subject.refused(KEY, EVIL)).toBe(false);
  });

  it("remember without a live window keeps nothing", () => {
    const subject = budget();
    subject.remember(KEY, EVIL);
    subject.charge(KEY);
    expect(subject.refused(KEY, EVIL)).toBe(false);

    clock = 60_000;
    subject.remember(KEY, EVIL);
    subject.charge(KEY);
    expect(subject.refused(KEY, EVIL)).toBe(false);
  });

  it("another principal's authorities are its own", () => {
    const subject = budget();
    subject.charge(KEY);
    subject.charge("agent:b");
    subject.remember(KEY, EVIL);
    expect([subject.refused(KEY, EVIL), subject.refused("agent:b", EVIL)]).toEqual([true, false]);
  });

  it("a window never holds more authorities than its limit", () => {
    const subject = budget();
    subject.charge(KEY);
    const authorities = ["a.example:443", "b.example:443", "c.example:443", "d.example:443"];
    for (const authority of authorities) subject.remember(KEY, authority);
    expect(authorities.map((authority) => subject.refused(KEY, authority))).toEqual([
      true,
      true,
      true,
      false,
    ]);
  });
});
