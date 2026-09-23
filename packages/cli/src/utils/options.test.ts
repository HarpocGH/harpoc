import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { parseIntOption, parsePositiveInteger } from "./options.js";

function refusalOf(run: () => unknown): unknown {
  try {
    run();
  } catch (err) {
    return err;
  }
  return undefined;
}

function expectInvalidInput(run: () => unknown): void {
  expect(run).toThrow(VaultError);
  expect(refusalOf(run)).toEqual(expect.objectContaining({ code: ErrorCode.INVALID_INPUT }));
}

describe("parseIntOption", () => {
  let exitSpy: MockInstance;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
  });

  afterEach(() => {
    exitSpy.mockRestore();
  });

  it("returns an in-range integer", () => {
    expect(parseIntOption("30", "renew-before-days", 1, 3650)).toBe(30);
  });

  it("accepts both bounds inclusively", () => {
    expect(parseIntOption("0", "callback port", 0, 65535)).toBe(0);
    expect(parseIntOption("65535", "callback port", 0, 65535)).toBe(65535);
  });

  it("refuses a non-numeric value naming the label and the range", () => {
    expectInvalidInput(() => parseIntOption("abc", "timeout", 1, 86400));
    expect(() => parseIntOption("abc", "timeout", 1, 86400)).toThrow(
      'Invalid timeout "abc". Must be 1-86400.',
    );
  });

  it("refuses a fractional value", () => {
    expectInvalidInput(() => parseIntOption("1.5", "renew-before-days", 1, 3650));
  });

  it("refuses a value below the minimum", () => {
    expectInvalidInput(() => parseIntOption("0", "renew-before-days", 1, 3650));
  });

  it("refuses a value above the maximum", () => {
    expectInvalidInput(() => parseIntOption("3651", "renew-before-days", 1, 3650));
  });

  it("refuses a negative value", () => {
    expectInvalidInput(() => parseIntOption("-1", "callback port", 0, 65535));
  });

  it.each(["0x10", "1e2", " 5 ", "5.0", "+5", ""])(
    "refuses the non-decimal form %j",
    (value: string) => {
      expectInvalidInput(() => parseIntOption(value, "callback port", 0, 65535));
    },
  );

  it("never exits the process itself — the command's error path renders the refusal (CM-6)", () => {
    expect(refusalOf(() => parseIntOption("abc", "timeout", 1, 86400))).toBeInstanceOf(VaultError);
    expect(exitSpy).not.toHaveBeenCalled();
  });
});

describe("parsePositiveInteger (P1bF-2)", () => {
  it.each(["5abc", "1.5", "1e3", "0", "", " 7", "-1", "0x10"])(
    "refuses %j as INVALID_INPUT with the caller's message",
    (value) => {
      let caught: unknown;
      try {
        parsePositiveInteger(value, "--expires must be a positive number of minutes");
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(VaultError);
      expect((caught as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
      expect((caught as VaultError).message).toBe("--expires must be a positive number of minutes");
    },
  );

  it("parses a decimal integer of at least 1", () => {
    expect(parsePositiveInteger("7", "m")).toBe(7);
    expect(parsePositiveInteger("1", "m")).toBe(1);
  });
});
