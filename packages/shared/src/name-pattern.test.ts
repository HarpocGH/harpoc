import { describe, expect, it } from "vitest";

import {
  isValidSecretNamePattern,
  matchesSecretNamePattern,
  matchesSecretNameScope,
} from "./name-pattern.js";

// ---------------------------------------------------------------------------
// matchesSecretNamePattern
// ---------------------------------------------------------------------------

describe("matchesSecretNamePattern", () => {
  it("matches a literal pattern only exactly", () => {
    expect(matchesSecretNamePattern("db-prod", "db-prod")).toBe(true);
    expect(matchesSecretNamePattern("db-prod2", "db-prod")).toBe(false);
    expect(matchesSecretNamePattern("db-pro", "db-prod")).toBe(false);
  });

  it("matches a trailing wildcard (thesis §4.7 worked example db-*)", () => {
    expect(matchesSecretNamePattern("db-prod", "db-*")).toBe(true);
    expect(matchesSecretNamePattern("db-staging", "db-*")).toBe(true);
    expect(matchesSecretNamePattern("db-", "db-*")).toBe(true);
    expect(matchesSecretNamePattern("api-key", "db-*")).toBe(false);
    expect(matchesSecretNamePattern("mydb-prod", "db-*")).toBe(false);
  });

  it("matches leading and inner wildcards", () => {
    expect(matchesSecretNamePattern("api-prod", "*-prod")).toBe(true);
    expect(matchesSecretNamePattern("api-dev", "*-prod")).toBe(false);
    expect(matchesSecretNamePattern("api-github-key", "api-*-key")).toBe(true);
    expect(matchesSecretNamePattern("api-key", "api-*-key")).toBe(false);
  });

  it("supports multiple wildcards and the match-all pattern", () => {
    expect(matchesSecretNamePattern("a-b-c", "*-*-*")).toBe(true);
    expect(matchesSecretNamePattern("anything", "*")).toBe(true);
  });

  it("is case-sensitive", () => {
    expect(matchesSecretNamePattern("db-prod", "DB-*")).toBe(false);
  });

  it("treats every non-wildcard character literally (no regex surface)", () => {
    expect(matchesSecretNamePattern("dbx", "db.")).toBe(false);
    expect(matchesSecretNamePattern("db.", "db.")).toBe(true);
    expect(matchesSecretNamePattern("a", "[a]")).toBe(false);
    expect(matchesSecretNamePattern("[a]", "[a]")).toBe(true);
    expect(matchesSecretNamePattern("dbdb", "(db)+")).toBe(false);
  });

  it("does not let prefix and suffix anchors overlap", () => {
    expect(matchesSecretNamePattern("aba", "ab*ba")).toBe(false);
    expect(matchesSecretNamePattern("abba", "ab*ba")).toBe(true);
    expect(matchesSecretNamePattern("abXba", "ab*ba")).toBe(true);
  });

  it("collapses consecutive wildcards", () => {
    expect(matchesSecretNamePattern("ab", "a**b")).toBe(true);
    expect(matchesSecretNamePattern("aXb", "a**b")).toBe(true);
    expect(matchesSecretNamePattern("aX", "a**b")).toBe(false);
    expect(matchesSecretNamePattern("anything", "**")).toBe(true);
    expect(matchesSecretNamePattern("", "*")).toBe(true);
  });

  it("requires middle segments in order", () => {
    expect(matchesSecretNamePattern("a-b-c", "a*b*c")).toBe(true);
    expect(matchesSecretNamePattern("bc", "*b*c*")).toBe(true);
    expect(matchesSecretNamePattern("cb", "*b*c*")).toBe(false);
  });

  it("does not let a middle segment borrow from the suffix anchor", () => {
    expect(matchesSecretNamePattern("ab", "*ab*b")).toBe(false);
    expect(matchesSecretNamePattern("abb", "*ab*b")).toBe(true);
  });

  it("handles adversarial many-wildcard patterns without backtracking (ReDoS)", () => {
    const nonMatching = "a".repeat(254) + "b";
    const start = performance.now();
    expect(matchesSecretNamePattern(nonMatching, "*a".repeat(20))).toBe(false);
    expect(matchesSecretNamePattern("a".repeat(255), "*a".repeat(20) + "*")).toBe(true);
    expect(matchesSecretNamePattern(nonMatching, "*a".repeat(126) + "*")).toBe(true);
    expect(matchesSecretNamePattern(nonMatching, "*ab".repeat(84) + "*")).toBe(false);
    expect(performance.now() - start).toBeLessThan(200);
  });
});

// ---------------------------------------------------------------------------
// matchesSecretNameScope
// ---------------------------------------------------------------------------

describe("matchesSecretNameScope", () => {
  it("is unrestricted when the pattern list is absent or empty", () => {
    expect(matchesSecretNameScope("anything", undefined)).toBe(true);
    expect(matchesSecretNameScope("anything", [])).toBe(true);
  });

  it("admits a name matching any pattern", () => {
    expect(matchesSecretNameScope("db-prod", ["api-key", "db-*"])).toBe(true);
    expect(matchesSecretNameScope("api-key", ["api-key", "db-*"])).toBe(true);
  });

  it("denies a name matching no pattern", () => {
    expect(matchesSecretNameScope("github-token", ["api-key", "db-*"])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isValidSecretNamePattern
// ---------------------------------------------------------------------------

describe("isValidSecretNamePattern", () => {
  it.each(["db-prod", "db-*", "*", "*-prod", "api-*-key", "a_b-c*", "ABC123"])(
    "accepts %s",
    (pattern) => {
      expect(isValidSecretNamePattern(pattern)).toBe(true);
    },
  );

  it.each(["", "db prod", "db.prod", "db/*", "db?", "[a]", "(db)+", "db\\prod", "a".repeat(256)])(
    "rejects %s",
    (pattern) => {
      expect(isValidSecretNamePattern(pattern)).toBe(false);
    },
  );
});
