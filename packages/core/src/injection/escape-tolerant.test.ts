// packages/core/src/injection/escape-tolerant.test.ts
import { describe, it, expect } from "vitest";
import { findEscapeTolerant } from "./escape-tolerant.js";
import { expectAbsent } from "@harpoc/test-utils";

const R = "[REDACTED]";
const LITERAL_TOKEN = "tok-en";
const REPEATED_TOKEN = "ab";
const ESCAPE_LETTER_TOKEN = "u";
const ESCAPE_UNIT_TOKEN = "u0062";

/** The needle's literal occurrences and `findEscapeTolerant`'s matches, merged, each written as `replacement`. */
function redactEscapeTolerant(text: string, needle: string, replacement: string): string {
  const found: number[] = [];
  if (needle.length > 0) {
    for (let i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, i + 1)) {
      found.push(i, i + needle.length);
    }
  }
  findEscapeTolerant(text, needle, found);
  const spans: [number, number][] = [];
  for (let i = 0; i < found.length; i += 2)
    spans.push([found[i] as number, found[i + 1] as number]);
  spans.sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const [start, end] of spans) {
    const last = merged[merged.length - 1];
    if (last !== undefined && start < last[1]) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  let out = "";
  let cursor = 0;
  for (const [start, end] of merged) {
    out += text.slice(cursor, start) + replacement;
    cursor = end;
  }
  return out + text.slice(cursor);
}

describe("redactEscapeTolerant", () => {
  it("redacts a literal occurrence", () => {
    const out = redactEscapeTolerant(`a ${LITERAL_TOKEN} b`, LITERAL_TOKEN, R);
    expectAbsent(out, LITERAL_TOKEN);
    expect(out).toBe(`a ${R} b`);
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
    const out = redactEscapeTolerant(`x ${REPEATED_TOKEN} y \\u0061b z`, REPEATED_TOKEN, R);
    expectAbsent(out, REPEATED_TOKEN);
    expect(out).toBe(`x ${R} y ${R} z`);
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
    const out = redactEscapeTolerant("\\u0062", ESCAPE_LETTER_TOKEN, R);
    expectAbsent(out, ESCAPE_LETTER_TOKEN);
    expect(out).toBe(`\\${R}0062`);
  });

  it("never misses a value that appears literally in non-JSON output", () => {
    // Process stdout is not JSON: here `b` is six literal characters and
    // the credential really is present. This is what forbids the escape-unit
    // skip — losing this match would leak the credential.
    const out = redactEscapeTolerant(
      `printing token: \\${ESCAPE_UNIT_TOKEN} done`,
      ESCAPE_UNIT_TOKEN,
      R,
    );
    expectAbsent(out, ESCAPE_UNIT_TOKEN);
    expect(out).toBe(`printing token: \\${R} done`);
  });
});
