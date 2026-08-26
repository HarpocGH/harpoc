import { describe, expect, it } from "vitest";
import { isDecimalInteger } from "./decimal-integer.js";

describe("isDecimalInteger", () => {
  it.each(["0", "5", "007", "65535", "1440"])("accepts the plain decimal literal %j", (value) => {
    expect(isDecimalInteger(value)).toBe(true);
  });

  // Every one of these passes `Number.isInteger(Number(value))` — the surface
  // form is the contract for operator input, so they are refused.
  it.each(["0x10", "0b1010", "0o17", "1e2", " 5 ", "5.0", "+5", "-5", "", "5\n", "٥"])(
    "refuses %j",
    (value) => {
      expect(isDecimalInteger(value)).toBe(false);
    },
  );
});
