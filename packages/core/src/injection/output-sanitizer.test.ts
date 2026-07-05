import { describe, expect, it } from "vitest";
import { redactSecretEncodings } from "./output-sanitizer.js";

const SECRET = "sk-topsecretvalue-123456";

describe("redactSecretEncodings", () => {
  it("redacts the raw value", () => {
    const out = redactSecretEncodings(`token is ${SECRET} ok`, SECRET);
    expect(out).toBe("token is [REDACTED] ok");
    expect(out).not.toContain(SECRET);
  });

  it("redacts multiple occurrences", () => {
    const out = redactSecretEncodings(`${SECRET} and ${SECRET}`, SECRET);
    expect(out).toBe("[REDACTED] and [REDACTED]");
  });

  it("redacts the base64 form", () => {
    const b64 = Buffer.from(SECRET, "utf8").toString("base64");
    const out = redactSecretEncodings(`encoded: ${b64}`, SECRET);
    expect(out).not.toContain(b64);
    expect(out).toContain("[REDACTED]");
  });

  it("redacts the base64url form", () => {
    const b64url = Buffer.from(SECRET, "utf8").toString("base64url");
    const out = redactSecretEncodings(`encoded: ${b64url}`, SECRET);
    expect(out).not.toContain(b64url);
  });

  it("redacts the lowercase and uppercase hex form", () => {
    const hex = Buffer.from(SECRET, "utf8").toString("hex");
    expect(redactSecretEncodings(hex, SECRET)).toBe("[REDACTED]");
    expect(redactSecretEncodings(hex.toUpperCase(), SECRET)).toBe("[REDACTED]");
  });

  it("redacts the percent-encoded form", () => {
    const enc = encodeURIComponent(SECRET);
    // pick a secret that actually changes under encoding
    const s = "a b/c?d";
    const encoded = encodeURIComponent(s);
    const out = redactSecretEncodings(`q=${encoded}`, s);
    expect(out).not.toContain(encoded);
    void enc;
  });

  it("returns text unchanged when the secret is absent", () => {
    expect(redactSecretEncodings("nothing to see", SECRET)).toBe("nothing to see");
  });

  it("handles empty inputs", () => {
    expect(redactSecretEncodings("", SECRET)).toBe("");
    expect(redactSecretEncodings("text", "")).toBe("text");
  });

  it("does NOT redact an arbitrary transform (documented L3 residual)", () => {
    // Reversing the secret is a transform the filter cannot know about.
    const reversed = [...SECRET].reverse().join("");
    const out = redactSecretEncodings(`leak: ${reversed}`, SECRET);
    expect(out).toContain(reversed);
  });

  it("does NOT redact character-by-character chunking (documented L3 residual)", () => {
    const chunked = SECRET.split("").join("|");
    const out = redactSecretEncodings(chunked, SECRET);
    expect(out).toContain(chunked);
  });
});
