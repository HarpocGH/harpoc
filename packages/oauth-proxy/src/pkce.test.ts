import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateCodeChallenge, generateCodeVerifier } from "./pkce.js";

describe("generateCodeVerifier", () => {
  it("returns a 43-character string", () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(43);
  });

  it("uses only base64url characters", () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("generates unique verifiers", () => {
    const v1 = generateCodeVerifier();
    const v2 = generateCodeVerifier();
    expect(v1).not.toBe(v2);
  });
});

describe("generateCodeChallenge", () => {
  it("produces a base64url-encoded SHA-256 hash", () => {
    const verifier = "test-verifier-value";
    const challenge = generateCodeChallenge(verifier);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("is deterministic for the same verifier", () => {
    const verifier = generateCodeVerifier();
    const c1 = generateCodeChallenge(verifier);
    const c2 = generateCodeChallenge(verifier);
    expect(c1).toBe(c2);
  });

  it("produces different challenges for different verifiers", () => {
    const c1 = generateCodeChallenge("verifier-a");
    const c2 = generateCodeChallenge("verifier-b");
    expect(c1).not.toBe(c2);
  });

  it("matches manual SHA-256 + base64url computation", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expected = createHash("sha256").update(verifier).digest("base64url");
    const challenge = generateCodeChallenge(verifier);
    expect(challenge).toBe(expected);
  });

  it("does not contain padding characters", () => {
    // base64url should not have = padding
    for (let i = 0; i < 10; i++) {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier);
      expect(challenge).not.toContain("=");
      expect(challenge).not.toContain("+");
      expect(challenge).not.toContain("/");
    }
  });
});
