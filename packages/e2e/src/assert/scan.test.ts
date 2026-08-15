import { describe, it, expect } from "vitest";
import { encodingsOf } from "./encodings.js";
import { scan } from "./scan.js";

// Deliberately adversarial: the "/" and "+" force base64url to diverge from
// base64, the space and '"' force urlEncoded to diverge from raw. A tamer
// secret (e.g. "sk-live-abc123!") collapses to 4 distinct needles of 6 and
// would silently under-test the encoding set.
const SECRET = 'sk-live/ab+cd 123"x';

describe("encodingsOf", () => {
  it("covers raw, base64, base64url, hex in both cases, and URL encoding", () => {
    const labels = encodingsOf(SECRET).map((e) => e.label);
    expect(labels).toEqual(["raw", "base64", "base64url", "hex", "hexUpper", "urlEncoded"]);
  });

  it("deduplicates encodings that collapse onto the raw value", () => {
    // "abcdef" URL-encodes to itself, and its base64 carries neither "+" nor
    // "/", so three candidates collapse.
    const needles = encodingsOf("abcdef").map((e) => e.needle);
    expect(new Set(needles).size).toBe(needles.length);
    expect(needles.length).toBeLessThan(6);
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

describe("scan — escape tolerance and serialized depth (review 2026-08-14, F1/F4)", () => {
  const SECRET = 'tok/en"x';

  it("finds a value the PHP convention escaped", () => {
    const hits = scan(SECRET, { body: '{"echo":"tok\\/en\\"x"}' });
    expect(hits).toHaveLength(1);
    expect(hits[0]?.encoding).toContain("jsonEscaped");
  });

  it("finds a value at two levels of serialization", () => {
    // The MCP shape: result -> serialized HttpResult -> serialized body.
    const body = JSON.stringify({ echo: SECRET });
    const httpResult = JSON.stringify({ status: 200, body });
    const hits = scan(SECRET, { result: httpResult });
    expect(hits.length).toBeGreaterThan(0);
  });

  it("still finds a plain raw value (negative control)", () => {
    expect(scan("abc123", { k: "xx abc123 yy" })).toHaveLength(1);
  });

  it("finds nothing in an unrelated structure (negative control)", () => {
    expect(scan("abc123", { k: "nothing here", n: 5, deep: { s: "marker" } })).toEqual([]);
  });

  it("recursion is bounded by MAX_PARSE_DEPTH — found at the cap, not beyond it", () => {
    // The original "self-describing string" case (`{ s: '"\\"nested\\""' }`)
    // never reached JSON.parse at all: its trimmed content starts with `"`,
    // which fails the `{`/`[` prefilter, so it pinned neither the depth cap
    // nor the guard after it — it only proved scan() doesn't throw on ANY
    // input, true of almost every test in this file.
    //
    // A plain alphanumeric credential can't force descent either: JSON string
    // escaping leaves ordinary letters/digits untouched at any nesting depth,
    // so it is always findable as contiguous literal text at depth 0, no
    // matter how deeply it is wrapped. Only a credential containing an
    // escape-worthy character (a quote, here) accumulates one MORE escape
    // layer per wrap, which forces exactly one more JSON.parse to peel back
    // to something the one-layer-tolerant matcher can read directly — the
    // same mechanism as the drift test's nested-JSON case, iterated.
    const credential = 'depth-tok"en';
    const singlyEscaped = JSON.stringify({ echo: credential }); // 1 escape layer

    function wrapLayers(inner: string, n: number): string {
      let out = inner;
      for (let i = 0; i < n; i++) out = JSON.stringify({ next: out });
      return out;
    }

    // +6 wraps = 7 total escape layers, needing exactly 6 JSON.parse calls
    // (depth 0->1->2->3->4->5->6) to reach 1 layer — exactly MAX_PARSE_DEPTH
    // (raised to 6 in Task 4, nested-json-redaction plan, so the harness stays
    // strictly deeper than the vault's own 4-parse cap — decision D2). Found.
    const atCap = wrapLayers(singlyEscaped, 6);
    expect(scan(credential, { body: atCap }).length).toBeGreaterThan(0);

    // +7 wraps = 8 total escape layers, needing a 7th parse from depth 6 —
    // `depth < MAX_PARSE_DEPTH` refuses it (6 < 6 is false). Not found: the
    // cap is doing something, not merely failing to throw.
    const beyondCap = wrapLayers(singlyEscaped, 7);
    expect(scan(credential, { body: beyondCap })).toEqual([]);
  });

  it("does not misread a successfully-parsed leaf; a JSON-shaped-but-unparsed leaf stays a string", () => {
    // scan.ts's two descent safety limits are `depth < MAX_PARSE_DEPTH`
    // (exercised above, in both directions) and
    // `typeof parsed === "object" && parsed !== null` immediately after a
    // successful `JSON.parse`. The second is NOT independently exercisable
    // through this file's only entry point, `scan()`: the prefilter only
    // attempts a parse when trimmed text starts with `{` or `[`, and by JSON
    // grammar a SUCCESSFUL parse of such text can only ever yield an object
    // or an array — never a bare string/number/boolean/null — so as written
    // today the guard is defensive-only (verified directly: there is no text
    // for which the prefilter passes and `JSON.parse` returns a non-object).
    // What IS independently testable is the prefilter's own decision: a leaf
    // that merely LOOKS JSON-shaped — a quoted string, a bare number, a bare
    // boolean — but does not start with `{`/`[` is left as an ordinary
    // string and scanned directly, never handed to `JSON.parse`.
    const credential = "leaf-primitive-abc";
    const hits = scan(credential, {
      quoted: `"${credential}"`,
      number: "12345",
      boolean: "true",
    });
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ path: "$.quoted" });
  });
});
