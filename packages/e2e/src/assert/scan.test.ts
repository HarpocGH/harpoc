import { describe, it, expect } from "vitest";
import { encodingsOf } from "./encodings.js";
import { scan } from "./scan.js";

// Deliberately adversarial: the "/" and "+" force base64url to diverge from
// base64, the space and '"' force urlEncoded and jsonEscaped to diverge from
// raw. A tamer secret (e.g. "sk-live-abc123!") collapses to 4 distinct needles
// of 7 and would silently under-test the encoding set.
const SECRET = 'sk-live/ab+cd 123"x';

describe("encodingsOf", () => {
  it("covers raw, base64, base64url, hex in both cases, URL and JSON escaping", () => {
    const labels = encodingsOf(SECRET).map((e) => e.label);
    expect(labels).toEqual([
      "raw",
      "base64",
      "base64url",
      "hex",
      "hexUpper",
      "urlEncoded",
      "jsonEscaped",
    ]);
  });

  it("deduplicates encodings that collapse onto the raw value", () => {
    // "abcdef" URL-encodes and JSON-escapes to itself, and its base64 carries
    // neither "+" nor "/", so three candidates collapse.
    const needles = encodingsOf("abcdef").map((e) => e.needle);
    expect(new Set(needles).size).toBe(needles.length);
    expect(needles.length).toBeLessThan(7);
  });
});

describe("scan", () => {
  it("finds the credential in a nested string value", () => {
    const hits = scan(SECRET, { a: { b: [`Bearer ${SECRET}`] } });
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ encoding: "raw", position: "value", path: "$.a.b[0]" });
  });

  it("finds the credential in an OBJECT KEY (H3/L1)", () => {
    const hits = scan(SECRET, { rows: [{ [SECRET]: "value" }] });
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ position: "key" });
  });

  it("finds a base64-encoded leak", () => {
    const b64 = Buffer.from(SECRET, "utf8").toString("base64");
    const hits = scan(SECRET, { body: `payload=${b64}` });
    expect(hits[0]?.encoding).toBe("base64");
  });

  it("finds an uppercase hex leak", () => {
    const hex = Buffer.from(SECRET, "utf8").toString("hex").toUpperCase();
    const hits = scan(SECRET, { body: hex });
    expect(hits[0]?.encoding).toBe("hexUpper");
  });

  it("finds a credential carried in a Buffer", () => {
    const hits = scan(SECRET, { payload: Buffer.from(SECRET, "utf8") });
    expect(hits[0]).toMatchObject({ encoding: "raw", position: "value" });
  });

  it("returns nothing for a clean object (negative control)", () => {
    expect(scan(SECRET, { status: 200, body: "[REDACTED]", rows: [{ id: 1 }] })).toEqual([]);
  });

  it("survives a circular reference", () => {
    const node: Record<string, unknown> = { safe: "ok" };
    node["self"] = node;
    expect(() => scan(SECRET, node)).not.toThrow();
  });
});
