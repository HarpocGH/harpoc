import { describe, expect, it } from "vitest";
import { isResponseModeAllowed } from "./response-mode.js";

describe("isResponseModeAllowed", () => {
  // Exhaustive 3×3: the tighten-only comparison is the security core of the
  // response_mode feature — a flipped inequality would make it loosen-only.
  it.each([
    ["full", "full", true],
    ["full", "filtered", true],
    ["full", "status_only", true],
    ["filtered", "full", false],
    ["filtered", "filtered", true],
    ["filtered", "status_only", true],
    ["status_only", "full", false],
    ["status_only", "filtered", false],
    ["status_only", "status_only", true],
  ] as const)("floor %s, requested %s → %s", (floor, requested, allowed) => {
    expect(isResponseModeAllowed(floor, requested)).toBe(allowed);
  });
});
