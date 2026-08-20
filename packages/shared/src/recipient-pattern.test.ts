import { describe, expect, it } from "vitest";

import { matchesRecipientPattern } from "./recipient-pattern.js";

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
