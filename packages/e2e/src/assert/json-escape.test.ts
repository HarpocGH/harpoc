import { describe, it, expect } from "vitest";
import { findEscapeTolerant } from "./json-escape.js";

describe("findEscapeTolerant", () => {
  it("finds a literal occurrence and reports it unescaped", () => {
    const [hit] = findEscapeTolerant("a tok-en b", "tok-en");
    expect(hit).toMatchObject({ start: 2, end: 8, escaped: false });
  });

  it("finds the PHP-escaped solidus and reports it escaped", () => {
    const [hit] = findEscapeTolerant('{"k":"tok\\/en"}', "tok/en");
    expect(hit?.escaped).toBe(true);
  });

  it("finds an all-\\uXXXX value in either hex case", () => {
    expect(findEscapeTolerant('"\\u0061\\u0062"', "ab")).toHaveLength(1);
    expect(findEscapeTolerant('"\\u0061\\u0042"', "aB")).toHaveLength(1);
  });

  it("finds a mixed-convention value", () => {
    expect(findEscapeTolerant('"to\\u006B\\/en"', "tok/en")).toHaveLength(1);
  });

  it("finds a surrogate pair escaped as two units", () => {
    expect(findEscapeTolerant('"\\ud83d\\ude00"', "\u{1F600}")).toHaveLength(1);
  });

  it("finds every occurrence", () => {
    expect(findEscapeTolerant("ab \\u0061b ab", "ab")).toHaveLength(3);
  });

  it("finds nothing when the value is absent", () => {
    expect(findEscapeTolerant('"tok\\/eX"', "tok/en")).toEqual([]);
  });

  it("finds nothing for an empty needle", () => {
    expect(findEscapeTolerant("abc", "")).toEqual([]);
  });
});
