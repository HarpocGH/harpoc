import { describe, expect, it } from "vitest";
import { findEscapeTolerant } from "./escape-tolerant.js";
import { randomCases } from "./__fixtures__/redact-cases.js";

const LITERAL_NEEDLE = "tok/en";

const SIMPLE_ESCAPES: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

function consume(text: string, at: number, wanted: string): number {
  if (at >= text.length) return 0;
  if (text[at] === "\\") {
    const next = text[at + 1];
    if (next !== undefined) {
      const simple = SIMPLE_ESCAPES[next];
      if (simple !== undefined) return simple === wanted ? 2 : 0;
      const digits = text.slice(at + 2, at + 6);
      if (next === "u" && /^[0-9a-fA-F]{4}$/.test(digits)) {
        return String.fromCharCode(Number.parseInt(digits, 16)) === wanted ? 6 : 0;
      }
    }
  }
  return text[at] === wanted ? 1 : 0;
}

function matchAt(text: string, start: number, needle: string): number {
  let at = start;
  for (let i = 0; i < needle.length; i++) {
    const step = consume(text, at, needle[i] as string);
    if (step === 0) return -1;
    at += step;
  }
  return at;
}

describe("findEscapeTolerant", () => {
  it("every start at which the needle matches is reported", () => {
    let reported = 0;
    for (const { text, values } of randomCases(7, 500)) {
      for (const needle of values) {
        const expected: number[] = [];
        for (let start = 0; start < text.length; start++) {
          const end = matchAt(text, start, needle);
          if (end === -1) continue;
          if (text.slice(start, end).includes("\\")) expected.push(start, end);
          else expect(text.slice(start, end)).toBe(needle);
        }

        expect(findEscapeTolerant(text, needle)).toEqual(expected);
        reported += expected.length / 2;
      }
    }
    expect(reported).toBeGreaterThan(100);
  });

  it("a text without a backslash reports nothing", () => {
    expect(findEscapeTolerant(`a ${LITERAL_NEEDLE} b ${LITERAL_NEEDLE}`, LITERAL_NEEDLE)).toEqual(
      [],
    );
  });
});
