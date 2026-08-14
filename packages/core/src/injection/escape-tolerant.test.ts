// packages/core/src/injection/escape-tolerant.test.ts
import { describe, it, expect } from "vitest";
import { redactEscapeTolerant } from "./escape-tolerant.js";

const R = "[REDACTED]";

describe("redactEscapeTolerant", () => {
  it("redacts a literal occurrence", () => {
    expect(redactEscapeTolerant("a tok-en b", "tok-en", R)).toBe(`a ${R} b`);
  });

  it("redacts the PHP convention, which escapes the solidus", () => {
    // json_encode without JSON_UNESCAPED_SLASHES. The V8 needle never matches this.
    expect(redactEscapeTolerant('{"k":"tok\\/en"}', "tok/en", R)).toBe(`{"k":"${R}"}`);
  });

  it("redacts the all-\\uXXXX convention in either hex case", () => {
    expect(redactEscapeTolerant('{"k":"\\u0061\\u0062"}', "ab", R)).toBe(`{"k":"${R}"}`);
    expect(redactEscapeTolerant('{"k":"\\u0061\\u0042"}', "aB", R)).toBe(`{"k":"${R}"}`);
  });

  it("redacts a mixed convention no single encoder emits", () => {
    // The adversarial case: half literal, half escaped.
    expect(redactEscapeTolerant('{"k":"to\\u006B\\/en"}', "tok/en", R)).toBe(`{"k":"${R}"}`);
  });

  it("redacts the V8 convention (quote and backslash) it already handled", () => {
    expect(redactEscapeTolerant('{"k":"a\\"b\\\\c"}', 'a"b\\c', R)).toBe(`{"k":"${R}"}`);
  });

  it("redacts a non-ASCII character escaped by Python's ensure_ascii", () => {
    expect(redactEscapeTolerant('{"k":"t\\u00fcr"}', "tür", R)).toBe(`{"k":"${R}"}`);
  });

  it("redacts a non-BMP character as a surrogate pair", () => {
    expect(redactEscapeTolerant('{"k":"\\ud83d\\ude00"}', "\u{1F600}", R)).toBe(`{"k":"${R}"}`);
  });

  it("redacts every occurrence, not just the first", () => {
    expect(redactEscapeTolerant("x ab y \\u0061b z", "ab", R)).toBe(`x ${R} y ${R} z`);
  });

  it("leaves a non-match untouched", () => {
    expect(redactEscapeTolerant('{"k":"tok\\/eX"}', "tok/en", R)).toBe('{"k":"tok\\/eX"}');
  });

  it("returns the text unchanged for an empty needle", () => {
    expect(redactEscapeTolerant("abc", "", R)).toBe("abc");
  });

  it("redacts a value spelled entirely in escapes without disturbing the surrounding JSON", () => {
    const out = redactEscapeTolerant('{"k":"\\u0061\\u0062c"}', "abc", R);
    expect(JSON.parse(out)).toEqual({ k: R });
  });

  it("accepts over-redaction: a match may begin inside an unrelated escape", () => {
    // `b` decodes to "b", not "u" — so in JSON this is a false positive.
    // It is tolerated on purpose: the alternative (skipping whole escape units
    // on a failed attempt) would miss the case pinned below, and a missed
    // redaction is the one failure this layer must not have.
    expect(redactEscapeTolerant("\\u0062", "u", R)).toBe(`\\${R}0062`);
  });

  it("never misses a value that appears literally in non-JSON output", () => {
    // Process stdout is not JSON: here `b` is six literal characters and
    // the credential really is present. This is what forbids the escape-unit
    // skip — losing this match would leak the credential.
    const out = redactEscapeTolerant("printing token: \\u0062 done", "u0062", R);
    expect(out).toBe(`printing token: \\${R} done`);
  });
});
