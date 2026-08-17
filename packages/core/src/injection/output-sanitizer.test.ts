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

  it("preserves a __proto__ own-property key (not the inherited setter)", () => {
    // `JSON.parse` builds object properties via CreateDataProperty, which never
    // consults the prototype chain, so this produces a genuine own property
    // literally named "__proto__" — the same shape a downstream server's JSON
    // response arrives in. A literal `{ __proto__: "x" }` object expression
    // would NOT reproduce the bug (that syntax is grammar-special-cased to set
    // the prototype instead of creating a property), so the fixture must be
    // built by parsing, not by writing the key directly in source.
    const input: unknown = JSON.parse('{"__proto__":"keep-me","note":"hello"}');
    expect(Object.prototype.hasOwnProperty.call(input as object, "__proto__")).toBe(true);

    const out = mapStringLeaves(input, redact) as Record<string, unknown>;

    // The walker's rebuilt object must still behave like a normal object
    // everywhere else uses it: unaffected prototype, and the "__proto__"
    // value reachable as a real own property, not silently dropped or (worse,
    // for an object-typed value) actually repointing the result's prototype.
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(out, "__proto__")?.value).toBe("keep-me");
    expect(out.note).toBe("hello");
    expect(JSON.stringify(out)).toBe('{"__proto__":"keep-me","note":"hello"}');
  });
});

describe("redactSecretEncodings — JSON escaping conventions (review 2026-08-14, F1)", () => {
  it("redacts a credential the PHP convention escaped", () => {
    const secret = "sk-live/abc";
    const body = `{"echo":"sk-live\\/abc"}`;
    expect(redactSecretEncodings(body, secret)).not.toContain("sk-live");
  });

  it("redacts a credential Python's ensure_ascii escaped", () => {
    const secret = "sk-tür-1";
    const body = `{"echo":"sk-t\\u00fcr-1"}`;
    const out = redactSecretEncodings(body, secret);
    expect(out).not.toContain("\\u00fc");
    expect(out).toContain("[REDACTED]");
  });

  it("redacts the BASE64 form when the backend escaped its solidus", () => {
    // The bypass that survived the 2026-08-13 fix: base64 alphabets contain "/".
    // (Deviation from the brief's fixture: pure low-ASCII input can only ever
    // land a "/" in base64 output at a 4th-char position, which requires a "?"
    // byte at an input offset ≡ 2 (mod 3) — no letter/digit/dash string can hit
    // it, verified: the brief's original secret's base64 never contains "/".)
    const secret = "sk?credential-with-slash-in-b64-xyz";
    const b64 = Buffer.from(secret, "utf8").toString("base64");
    expect(b64).toContain("/"); // guard: this fixture must actually exercise the case
    const body = `{"echo":"${b64.replace(/\//g, "\\/")}"}`;
    expect(redactSecretEncodings(body, secret)).not.toContain(b64.split("/")[0]);
  });

  it("still redacts the plain raw form (negative control: no regression)", () => {
    expect(redactSecretEncodings("token=abc123", "abc123")).toBe("token=[REDACTED]");
  });

  it("leaves a benign marker untouched (negative control: not blanket redaction)", () => {
    expect(redactSecretEncodings('{"marker":"keep-me"}', "abc123")).toBe('{"marker":"keep-me"}');
  });
});

describe("redactSecretEncodings — backslash-probe wiring pins (review 2026-08-14, Task 2 deferred minor)", () => {
  // Both backslash short-circuits skip escape-aware work when the probed
  // string contains none. The probe must read the TEXT: a real credential
  // almost never contains a backslash, so probing the SECRET instead would
  // skip these passes for virtually every credential — silently disabling
  // escape-tolerant redaction wholesale. The convention cases above catch
  // that mutation only incidentally; these two exist to catch it by name.

  it("the flat pass probes the text: an escaped occurrence of a backslash-free secret is redacted", () => {
    const secret = "wiring-pin-token";
    expect(secret).not.toContain("\\");
    // Deliberately NOT a JSON document: on a parseable body the structural
    // descent would decode the escape via JSON.parse and rescue a mis-wired
    // flat pass, so only a non-JSON fixture makes this pin discriminate.
    const body = "token=wiring-pin-tok\\u0065n";
    expect(body).not.toContain(secret);
    expect(redactSecretEncodings(body, secret)).toBe("token=[REDACTED]");
  });

  it("the descent gate probes the text: a nested occurrence of a backslash-free secret is redacted", () => {
    const secret = 'wiring"pin-2';
    expect(secret).not.toContain("\\");
    // Two escape layers deep: the flat tolerant pass decodes only one, so the
    // structural descent is the only path to this occurrence — a gate probing
    // the (backslash-free) secret would never open it.
    const body = JSON.stringify({ data: JSON.stringify({ echo: secret }) });
    expect(redactSecretEncodings(body, secret)).not.toContain("pin-2");
  });
});

describe("mapStringLeaves — JSON descent budget", () => {
  // An EXACT-match mapper, not a substring one. A substring mapper would rewrite
  // the word wherever it appears, including inside the serialized document at
  // the outer level — so every descent case would pass without any descent
  // happening. Requiring the whole leaf to equal the needle makes reaching the
  // inner leaf the only way these assertions can hold.
  const shout = (s: string): string => (s === "secret" ? "SHOUTED" : s);

  it("does not descend by default (today's behaviour)", () => {
    const leaf = JSON.stringify({ inner: "secret" });
    const out = mapStringLeaves({ payload: leaf }, shout) as { payload: string };
    expect(out.payload).toBe(leaf);
  });

  it("descends into a string leaf that is itself JSON", () => {
    const leaf = JSON.stringify({ inner: "secret" });
    const out = mapStringLeaves({ payload: leaf }, shout, { descendJson: 1 }) as {
      payload: string;
    };
    expect(JSON.parse(out.payload)).toEqual({ inner: "SHOUTED" });
  });

  it("descends into a string leaf that is itself a JSON array", () => {
    // The walker's trim check accepts a leaf trimming to "{" OR "[" — a
    // top-level array body is a routine API shape (e.g. a bulk-list
    // endpoint), and until now nothing exercised that second branch.
    const leaf = JSON.stringify(["secret", "other"]);
    const out = mapStringLeaves({ payload: leaf }, shout, { descendJson: 1 }) as {
      payload: string;
    };
    expect(JSON.parse(out.payload)).toEqual(["SHOUTED", "other"]);
  });

  it("stops at the budget", () => {
    const deep = JSON.stringify({ b: JSON.stringify({ c: "secret" }) });
    const out = mapStringLeaves({ a: deep }, shout, { descendJson: 1 }) as { a: string };
    // One descent reaches `b`, whose value is still a serialized document. The
    // budget is spent, so the leaf inside it is never visited.
    expect(out.a).toContain("secret");
  });

  it("descends far enough when the budget allows", () => {
    const deep = JSON.stringify({ b: JSON.stringify({ c: "secret" }) });
    const out = mapStringLeaves({ a: deep }, shout, { descendJson: 2 }) as { a: string };
    expect(out.a).not.toContain("secret");
  });

  it("keeps a leaf byte-identical when nothing inside it changed", () => {
    const leaf = '{ "inner" :  "harmless" }'; // deliberately odd whitespace
    const out = mapStringLeaves({ payload: leaf }, shout, { descendJson: 2 }) as {
      payload: string;
    };
    expect(out.payload).toBe(leaf);
  });

  it("applies the mapper to a non-JSON leaf and returns it otherwise untouched", () => {
    // "Attempts no parse" is the implementation's claim (the `{`/`[`
    // prefilter), not something this assertion can observe — it cannot
    // distinguish "not attempted" from "attempted and safely failed", so the
    // name states only what it pins (2026-08-15 deferred minor).
    const out = mapStringLeaves({ payload: "secret" }, shout, { descendJson: 2 }) as {
      payload: string;
    };
    expect(out.payload).toBe("SHOUTED");
  });

  it("returns a malformed JSON-looking leaf as the mapper left it", () => {
    // The fixture must make `mapped !== value`, or the assertion cannot
    // distinguish the catch returning the MAPPED leaf from it returning the
    // original — and a regression to the original would silently drop the
    // flat redaction on truncated JSON bodies (2026-08-15 deferred minor:
    // the previous fixture used the exact-match mapper, for which the two
    // are identical, so the catch path was verified by reading, pinned by
    // nothing).
    const redactish = (s: string): string => s.replace("secret", "[X]");
    const out = mapStringLeaves({ payload: '{"inner": "secret"' }, redactish, {
      descendJson: 2,
    }) as { payload: string };
    expect(out.payload).toBe('{"inner": "[X]"');
  });

  it("maps keys at depth, with the collision rule (H3)", () => {
    // `SHOUTED` FIRST on purpose: the suffix rule only guards a key the mapper
    // actually changed, so with the other order the unchanged `SHOUTED` would
    // overwrite the mapped one. That is pre-existing behaviour, pinned as it is.
    const leaf = JSON.stringify({ SHOUTED: 2, secret: 1 });
    const out = mapStringLeaves({ payload: leaf }, shout, { descendJson: 1 }) as {
      payload: string;
    };
    const parsed = JSON.parse(out.payload) as Record<string, number>;
    expect(Object.keys(parsed).sort()).toEqual(["SHOUTED", "SHOUTED_2"]);
  });
});

describe("redactSecretEncodings — nested JSON documents", () => {
  const wrap = (inner: string): string => JSON.stringify({ data: inner });
  const t1 = (secret: string): string => JSON.stringify({ echo: secret });

  it("redacts a quote-bearing credential behind a webhook envelope", () => {
    const secret = 'tok"en-x';
    const body = wrap(t1(secret));
    const out = redactSecretEncodings(body, secret);
    expect(out).not.toContain("en-x");
    expect(JSON.parse(out)).toBeTypeOf("object");
  });

  it("redacts a backslash-bearing credential behind a webhook envelope", () => {
    const secret = "dom\\user-pw";
    const out = redactSecretEncodings(wrap(t1(secret)), secret);
    expect(out).not.toContain("user-pw");
  });

  it("redacts a non-ASCII credential escaped by an ensure_ascii encoder", () => {
    const secret = "passwörd-1";
    // What Python's json.dumps emits, then wrapped by the outer document.
    const inner = '{"echo":"passw\\u00f6rd-1"}';
    const out = redactSecretEncodings(wrap(inner), secret);
    expect(out).not.toContain("passw");
  });

  it("redacts through four parses and is blind at five (the D2 boundary)", () => {
    const secret = 'tok"en-y';
    const t5 = wrap(wrap(wrap(wrap(t1(secret)))));
    expect(redactSecretEncodings(t5, secret)).not.toContain("en-y");
    const t6 = wrap(t5);
    expect(redactSecretEncodings(t6, secret)).toBe(t6);
  });

  it("redacts a credential in KEY position at depth", () => {
    const secret = 'tok"en-k';
    const body = wrap(JSON.stringify({ [secret]: 1 }));
    expect(redactSecretEncodings(body, secret)).not.toContain("en-k");
  });

  it("preserves a __proto__ key while redacting a sibling credential", () => {
    // A __proto__ own property at the TOP level (the object the structural
    // descent's outermost JSON.parse produces directly) so the walker's
    // rebuild of THAT object is what the final output actually returns — not
    // a deeper rebuild whose result gets discarded because nothing changed at
    // that level. The `nested` credential is one JSON.stringify layer down
    // (same shape as `t1`/`wrap` elsewhere in this file), so the flat pass
    // alone cannot find it and the descent must fire, forcing this object to
    // be re-serialized and exercising the __proto__ accumulator bug.
    const secret = 'tok"en-p';
    const bodyObj: Record<string, unknown> = { ["__proto__"]: "keep-me", nested: t1(secret) };
    const body = JSON.stringify(bodyObj);

    const out = redactSecretEncodings(body, secret);
    expect(out).not.toContain("en-p");

    const parsedOut = JSON.parse(out) as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(parsedOut, "__proto__")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(parsedOut, "__proto__")?.value).toBe("keep-me");
  });

  it("leaves a nested body byte-identical when nothing matches", () => {
    // This body DOES contain backslashes (nesting escapes the inner quotes), so
    // the descent runs and finds nothing — the point is that a clean response
    // is returned verbatim rather than re-serialized.
    const body = wrap(JSON.stringify({ echo: "harmless" }));
    expect(redactSecretEncodings(body, 'tok"en-z')).toBe(body);
  });

  it("returns a non-canonical clean body verbatim rather than re-serializing", () => {
    // Unlike the case above, this body is hand-written, not produced by
    // JSON.stringify: odd spacing and a number wide enough that IEEE-754
    // normalization would visibly change it. A `walked.changed` check that
    // had been removed would still pass the case above (JSON.stringify output
    // is already canonical and survives re-serialization byte-identically) —
    // only a non-canonical fixture can catch that regression.
    const body = '{ "data": "{\\"echo\\":\\"harmless\\"}", "id": 12345678901234567890 }';
    expect(body).toContain("\\");
    expect(redactSecretEncodings(body, 'tok"en-z')).toBe(body);
  });

  it("never parses a body without a backslash (the short-circuit)", () => {
    // No escaping anywhere, so no nested occurrence can exist. Pinned because
    // this is what keeps the common path at the measured 0.32 ms/MiB.
    const body = '{"data":{"echo":"harmless"},"n":1}';
    expect(body).not.toContain("\\");
    expect(redactSecretEncodings(body, 'tok"en-z')).toBe(body);
  });

  it("falls back to the flat result when the document does not parse", () => {
    const secret = 'tok"en-m';
    const truncated = wrap(t1(secret)).slice(0, -3);
    // No throw, and never weaker than the flat pass alone.
    expect(() => redactSecretEncodings(truncated, secret)).not.toThrow();
  });

  it("does not let re-serialization introduce the credential where it wasn't (monotonicity)", () => {
    // Reviewer-reproduced case (review 2026-08-15 fix wave): the structural
    // descent re-serializes the WHOLE object once anything inside it changed,
    // not just the leaf that changed. An untouched SIBLING leaf whose decoded
    // value holds a real newline character gets re-escaped through V8's
    // short-escape convention -- backslash followed by the literal letter
    // "n" -- which is byte-identical to a credential that happens to contain
    // a literal backslash immediately followed by "n". The sibling has
    // nothing to do with the credential; only re-serialization introduces
    // the collision.
    const secret = "DOMAIN\\name"; // runtime: D O M A I N BACKSLASH n a m e
    const envelope = JSON.stringify({ echo: secret });
    const dataField = JSON.stringify(envelope); // needs the descent to reach
    // Literal JSON text spelling the U+000A unicode escape for a real
    // newline, deliberately not V8's own short-escape form for it, so
    // neither the literal nor the escape-tolerant flat pass matches it up
    // front: its DECODED value has no backslash at all, only an actual
    // newline byte.
    const siblingRaw = '"DOMAIN\\u000Aame"';
    const body = `{"data":${dataField},"sibling":${siblingRaw}}`;

    const out = redactSecretEncodings(body, secret);

    expect(out).not.toContain(secret);
    const parsedOut = JSON.parse(out) as { data: string };
    expect(parsedOut.data).toContain("[REDACTED]");
    expect(JSON.parse(parsedOut.data)).toEqual({ echo: "[REDACTED]" });
  });

  it("skips the descent above the size guard", () => {
    const secret = 'tok"en-big';
    const inner = t1(secret);
    const padding = "x".repeat(5 * 1024 * 1024);
    const body = JSON.stringify({ pad: padding, data: inner });
    // Over the guard: the flat passes still run, the descent does not.
    expect(redactSecretEncodings(body, secret)).toContain("en-big");
  });
});
