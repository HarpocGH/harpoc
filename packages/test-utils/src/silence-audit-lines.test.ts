import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { silenceAuditLines } from "./silence-audit-lines.js";

describe("silenceAuditLines", () => {
  const seen: unknown[][] = [];
  let outer: MockInstance<typeof console.error>;

  beforeAll(() => {
    outer = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      seen.push(args);
    });
  });

  afterAll(() => {
    outer.mockRestore();
  });

  afterEach(() => {
    expect(console.error).toBe(outer);
  });

  silenceAuditLines();

  it("drops a line whose first argument starts with the audit tag", () => {
    seen.length = 0;
    console.error(
      "[audit] %s %s → %d principal=%s ip=%s",
      "GET",
      "/api/v1/health",
      200,
      "a",
      "unknown",
    );
    expect(seen).toEqual([]);
  });

  it("hands every other line to the function it replaced", () => {
    seen.length = 0;
    console.error("[harpoc] OAuth background flow failed (secret-1): provider offline");
    console.error("[auditor] not the tag");
    console.error(new Error("plain"));
    expect(seen).toHaveLength(3);
    expect(seen[0]).toEqual(["[harpoc] OAuth background flow failed (secret-1): provider offline"]);
  });

  it("installs the filter for the body of a test and passes every argument through", () => {
    expect(console.error).not.toBe(outer);
    seen.length = 0;
    console.error("still the outer spy");
    console.error("[harpoc] %s", "x");
    expect(seen).toEqual([["still the outer spy"], ["[harpoc] %s", "x"]]);
  });

  it("keeps the filter when a test restores a spy of its own", () => {
    seen.length = 0;
    const inner = vi.spyOn(console, "error");
    console.error("[audit] GET /api/v1/health → 200");
    console.error("first other line");
    expect(seen).toEqual([["first other line"]]);
    expect(inner).toHaveBeenCalledTimes(2);
    inner.mockRestore();
    console.error("[audit] GET /api/v1/health → 200");
    console.error("second other line");
    expect(seen).toEqual([["first other line"], ["second other line"]]);
  });
});
