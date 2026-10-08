import { describe, expect, it } from "vitest";

import { isValidRecipientPattern, matchesRecipientPattern } from "./recipient-pattern.js";

describe("matchesRecipientPattern", () => {
  it("exact match: local part case-sensitive, domain case-insensitive", () => {
    expect(matchesRecipientPattern("Ops@Example.COM", ["Ops@example.com"])).toBe(true);
    expect(matchesRecipientPattern("ops@example.com", ["Ops@example.com"])).toBe(false);
  });
  it("*@domain matches any local part on that domain only", () => {
    expect(matchesRecipientPattern("x@example.com", ["*@example.com"])).toBe(true);
    expect(matchesRecipientPattern("x@sub.example.com", ["*@example.com"])).toBe(false);
  });
  it("empty pattern list matches nothing", () => {
    expect(matchesRecipientPattern("x@example.com", [])).toBe(false);
  });
});

describe("isValidRecipientPattern", () => {
  it.each(["ops@example.com", "*@example.com", "a.b+c@sub.example-1.org"])("accepts %s", (p) => {
    expect(isValidRecipientPattern(p)).toBe(true);
  });
  it.each([
    ["ops*@example.com", "a partial-local wildcard"],
    ["*ops@example.com", "a leading partial-local wildcard"],
    ["*@*", "a wildcard domain"],
    ["a@b@example.com", "a double @"],
    ["o ps@example.com", "whitespace in the local part"],
    ["ops@exa mple.com", "whitespace in the domain"],
    ["@example.com", "an empty local part"],
    ["ops@", "an empty domain"],
    ["example.com", "no @"],
  ])("refuses %s (%s)", (p) => {
    expect(isValidRecipientPattern(p)).toBe(false);
  });
});
