import { describe, expect, it } from "vitest";
import { mapStringLeaves, redactSecretEncodings } from "./output-sanitizer.js";

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

  /**
   * A response body is normally JSON, so an endpoint that echoes the credential
   * hands it back escaped: a quote becomes \" and a backslash becomes \\. The
   * raw needle then does not appear in the body as contiguous bytes and the
   * value survives verbatim, one `JSON.parse` away from the model.
   *
   * This went unnoticed because every credential in the suite was
   * `[a-z0-9-]`, for which the escaped form is byte-identical to the raw one —
   * the class is invisible unless the value can actually be escaped.
   */
  it("redacts the JSON-escaped form", () => {
    const s = `tok${String.fromCharCode(34)}en${String.fromCharCode(92)}x`;
    const escaped = JSON.stringify(s).slice(1, -1);
    expect(escaped).not.toBe(s);

    const body = `{"credential":"${escaped}"}`;
    const out = redactSecretEncodings(body, s);
    expect(out).not.toContain(escaped);
    expect(out).toContain("[REDACTED]");
  });

  it("leaves a benign neighbour intact while redacting the escaped form", () => {
    const s = `a${String.fromCharCode(34)}b`;
    const body = `{"c":"${JSON.stringify(s).slice(1, -1)}","marker":"keep-me"}`;
    expect(redactSecretEncodings(body, s)).toContain("keep-me");
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

// H3: the walker feeds both redaction layers for MCP and database results, and
// the party choosing the key names is the downstream server (or a SQL column
// alias) — a value-only walk hands the credential to the model in key position.
describe("mapStringLeaves — key positions", () => {
  const redact = (s: string): string => redactSecretEncodings(s, SECRET);

  it("redacts the credential in an object key", () => {
    const out = mapStringLeaves({ [SECRET]: 1 }, redact);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(Object.keys(out as object)).toEqual(["[REDACTED]"]);
  });

  it("redacts key and value positions alike", () => {
    const out = mapStringLeaves({ [SECRET]: SECRET }, redact) as Record<string, unknown>;
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out["[REDACTED]"]).toBe("[REDACTED]");
  });

  it("redacts an encoded credential in a key", () => {
    const b64 = Buffer.from(SECRET, "utf8").toString("base64");
    const out = mapStringLeaves({ [b64]: "x" }, redact);
    expect(JSON.stringify(out)).not.toContain(b64);
  });

  it("reaches keys nested in objects and arrays", () => {
    const out = mapStringLeaves(
      { outer: [{ inner: { [SECRET]: "v" } }], [`pre-${SECRET}-post`]: 2 },
      redact,
    );
    expect(JSON.stringify(out)).not.toContain(SECRET);
  });

  it("keeps both entries when redaction collapses two keys onto one name", () => {
    const b64 = Buffer.from(SECRET, "utf8").toString("base64");
    const out = mapStringLeaves({ [SECRET]: "first", [b64]: "second" }, redact) as Record<
      string,
      unknown
    >;
    expect(Object.keys(out)).toHaveLength(2);
    expect(Object.values(out)).toEqual(expect.arrayContaining(["first", "second"]));
    expect(JSON.stringify(out)).not.toContain(SECRET);
  });

  it("leaves unrelated keys and the structure untouched", () => {
    const out = mapStringLeaves({ note: "hello", n: 1, list: [1, "two", null] }, redact);
    expect(out).toEqual({ note: "hello", n: 1, list: [1, "two", null] });
  });
});
