import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { parseIntOption } from "./options.js";

describe("parseIntOption", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it("returns an in-range integer", () => {
    expect(parseIntOption("30", "renew-before-days", 1, 3650)).toBe(30);
  });

  it("accepts both bounds inclusively", () => {
    expect(parseIntOption("0", "callback port", 0, 65535)).toBe(0);
    expect(parseIntOption("65535", "callback port", 0, 65535)).toBe(65535);
  });

  it("refuses a non-numeric value naming the label and the range", () => {
    expect(() => parseIntOption("abc", "timeout", 1, 86400)).toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Invalid timeout "abc". Must be 1-86400.'),
    );
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("refuses a fractional value", () => {
    expect(() => parseIntOption("1.5", "renew-before-days", 1, 3650)).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("refuses a value below the minimum", () => {
    expect(() => parseIntOption("0", "renew-before-days", 1, 3650)).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("refuses a value above the maximum", () => {
    expect(() => parseIntOption("3651", "renew-before-days", 1, 3650)).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("refuses a negative value", () => {
    expect(() => parseIntOption("-1", "callback port", 0, 65535)).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it.each(["0x10", "1e2", " 5 ", "5.0", "+5", ""])(
    "refuses the non-decimal form %j",
    (value: string) => {
      expect(() => parseIntOption(value, "callback port", 0, 65535)).toThrow("process.exit");
      expect(exitSpy).toHaveBeenCalledWith(1);
    },
  );
});
