import { describe, it, expect } from "vitest";
import {
  RECORD_REDACTION,
  assertOpaque,
  assertPresent,
  redactForDiagnostics,
  redactForRecord,
  sightings,
} from "./opacity.js";
import { serializeError } from "./serialize-error.js";
import { MAX_PARSE_DEPTH, scan } from "./scan.js";

/**
 * A scenario has to CLASSIFY an outcome (LEAKED vs OPAQUE) rather than assert
 * one, so it needs the same multi-channel, multi-encoding sweep `assertOpaque`
 * performs without the throw. Re-deriving it per scenario would let the two
 * drift, and the scenario copy would be the one nobody guard-flips.
 */
describe("sightings (non-throwing opacity sweep)", () => {
  it("reports nothing for a clean observation", () => {
    expect(sightings("sekret-value", { result: { ok: true, note: "[REDACTED]" } })).toEqual([]);
  });

  it("finds the credential and names the channel it surfaced in", () => {
    const hits = sightings("sekret-value", { stderr: "boom: sekret-value" });
    expect(hits).toHaveLength(1);
    expect(hits[0]?.path).toMatch(/^stderr/);
  });

  it("sweeps every channel assertOpaque covers, encoded forms included", () => {
    const secret = "sekret-value";
    const b64 = Buffer.from(secret, "utf8").toString("base64");
    const hits = sightings(secret, {
      result: { nested: { deep: b64 } },
      auditRows: [{ detail: secret }],
    });
    // Channel name is the path prefix before any index or member access.
    expect(hits.map((h) => /^[a-zA-Z]+/.exec(h.path)?.[0]).sort()).toEqual(["audit", "result"]);
  });
});

const SECRET = "sk-live-abc123!";

describe("serializeError", () => {
  it("exposes the non-enumerable message and stack", () => {
    const out = serializeError(new Error(`auth failed for ${SECRET}`));
    expect(JSON.stringify(out)).toContain(SECRET);
  });

  it("follows the cause chain", () => {
    const out = serializeError(new Error("outer", { cause: new Error(SECRET) }));
    expect(JSON.stringify(out)).toContain(SECRET);
  });

  it("wraps a non-Error throw", () => {
    expect(serializeError("plain string")).toEqual({ value: "plain string" });
  });

  it("survives a self-referencing cause chain", () => {
    const err = new Error("loop");
    (err as { cause?: unknown }).cause = err;
    expect(() => serializeError(err)).not.toThrow();
  });
});

describe("assertOpaque", () => {
  it("passes on a clean observation", () => {
    expect(() =>
      assertOpaque(SECRET, {
        result: { status: 200, body: "[REDACTED]" },
        auditRows: [{ success: true, detail: { context: "database" } }],
        stdout: "done",
        parentEnv: { PATH: "/usr/bin" },
      }),
    ).not.toThrow();
  });

  it("fails on a leak in the result", () => {
    expect(() => assertOpaque(SECRET, { result: { body: SECRET } })).toThrow(/result\.body/);
  });

  it("fails on a leak in a thrown error (H2)", () => {
    expect(() => assertOpaque(SECRET, { error: new Error(`refused: ${SECRET}`) })).toThrow(/error/);
  });

  it("fails on a leak in an audit row (M9)", () => {
    expect(() =>
      assertOpaque(SECRET, { auditRows: [{ detail: { stderr_tail: SECRET } }] }),
    ).toThrow(/audit/);
  });

  it("fails on a leak in child stderr", () => {
    expect(() => assertOpaque(SECRET, { stderr: `echo: ${SECRET}` })).toThrow(/stderr/);
  });

  it("fails on a leak in the parent environment", () => {
    expect(() => assertOpaque(SECRET, { parentEnv: { LEAK: SECRET } })).toThrow(/parentEnv/);
  });

  it("names every position it found, not just the first", () => {
    const err = (() => {
      try {
        assertOpaque(SECRET, { result: { a: SECRET, b: SECRET } });
        return null;
      } catch (e) {
        return e as Error;
      }
    })();
    expect(err?.message).toContain("2 position(s)");
  });
});

describe("assertPresent (negative control against blanket redaction)", () => {
  it("passes when the benign marker survived", () => {
    expect(() => assertPresent("keep-me", { result: { note: "keep-me" } })).not.toThrow();
  });

  it("fails when everything was redacted", () => {
    expect(() => assertPresent("keep-me", { result: { note: "[REDACTED]" } })).toThrow(/keep-me/);
  });
});

/**
 * I1 (test-review-2026-10-09): the record-time redaction behind
 * `EvidenceRecord.calls`. Its marker must differ from the sanitizer's, because
 * the sanitizer's `[REDACTED]` is one of the things a reader re-checks for.
 */
describe("redactForRecord (the record-time marker behind EvidenceRecord.calls)", () => {
  const secret = 'sk-record/ab+cd 123"x';

  it("replaces the credential and its encodings with a marker that is not the sanitizer's", () => {
    const b64 = Buffer.from(secret).toString("base64");
    const text = `plain ${secret}, base64 ${b64}, json ${JSON.stringify({ k: secret })}, kept [REDACTED]`;
    const out = redactForRecord(text, secret);
    expect(out).not.toContain(secret);
    expect(out).not.toContain(b64);
    expect(out).toContain(RECORD_REDACTION);
    expect(out).toContain("kept [REDACTED]");
    expect(RECORD_REDACTION).not.toBe("[REDACTED]");
    expect(redactForDiagnostics(text, secret)).not.toContain(RECORD_REDACTION);
  });

  it("takes several credentials and leaves a text without any of them untouched", () => {
    expect(redactForRecord("alpha-one beta-two", "alpha-one", "beta-two")).toBe(
      `${RECORD_REDACTION} ${RECORD_REDACTION}`,
    );
    expect(redactForRecord("clean", secret)).toBe("clean");
  });
});

describe("redactForRecord on nested JSON (the structural pass)", () => {
  const secret = 'sk-nested"credential\\x';

  it("marks a credential two and three JSON levels deep and keeps the text parseable", () => {
    const inner = JSON.stringify({ body: JSON.stringify({ token: secret, note: "kept" }) });
    const text = JSON.stringify({ content: [{ type: "text", text: inner }] });
    expect(scan(secret, text).length).toBeGreaterThan(0);
    const out = redactForRecord(text, secret);
    expect(scan(secret, out)).toEqual([]);
    expect(out).toContain(RECORD_REDACTION);
    const parsed = JSON.parse(out) as { content: Array<{ type: string; text: string }> };
    const leaf = JSON.parse(parsed.content[0]?.text ?? "{}") as { body: string };
    expect(JSON.parse(leaf.body)).toEqual({ token: RECORD_REDACTION, note: "kept" });
  });

  it("marks a credential sitting in an object key", () => {
    const text = JSON.stringify({ outer: JSON.stringify({ [secret]: "v" }) });
    const out = redactForRecord(text, secret);
    expect(scan(secret, out)).toEqual([]);
    expect(out).toContain(RECORD_REDACTION);
  });

  it("leaves a text without a nested sighting byte-identical, formatting included", () => {
    const text = JSON.stringify({ a: JSON.stringify({ b: "clean" }) }, null, 2);
    expect(redactForRecord(text, secret)).toBe(text);
  });

  it("marks in place a credential the opacity scan sights at its deepest parse (MAX_PARSE_DEPTH)", () => {
    const text = nest(secret, MAX_PARSE_DEPTH + 1);
    expect(scan(secret, text).length).toBeGreaterThan(0);
    const out = redactForRecord(text, secret);
    expect(scan(secret, out)).toEqual([]);
    expect(out).toContain(RECORD_REDACTION);
  });

  it("reaches no deeper than the opacity scan: one escape layer beyond, neither sights nor marks (characterization)", () => {
    const text = nest(secret, MAX_PARSE_DEPTH + 2);
    expect(scan(secret, text)).toEqual([]);
    expect(redactForRecord(text, secret)).toBe(text);
  });
});

describe("redactForRecord on a credential whose own backslash reads as a JSON escape (C6-ae)", () => {
  const credential = "pw\\tail";

  it("marks it raw at level 0, for the record and for diagnostics", () => {
    expect(redactForRecord(`x ${credential} y`, credential)).toBe(`x ${RECORD_REDACTION} y`);
    expect(redactForDiagnostics(`x ${credential} y`, credential)).toBe("x [REDACTED] y");
  });

  it("marks the literal and the level-1 escaped form in one JSON text, each once", () => {
    const text = `{"raw":"${credential}","escaped":${JSON.stringify(credential)}}`;
    expect(redactForRecord(text, credential)).toBe(
      `{"raw":"${RECORD_REDACTION}","escaped":"${RECORD_REDACTION}"}`,
    );
  });

  it("marks a span both readings reach as one range", () => {
    const needle = "\\u0041";
    expect(redactForRecord(`${JSON.stringify(needle)} ${needle}`, needle)).toBe(
      `"${RECORD_REDACTION}" ${RECORD_REDACTION}`,
    );
  });

  it("leaves no sighting at any escape layer the opacity scan reaches, the literal included", () => {
    const outcomes: Array<{ layers: number; sighted: number; marked: boolean }> = [];
    const expected: typeof outcomes = [];
    for (let layers = 0; layers <= MAX_PARSE_DEPTH + 2; layers++) {
      const out = redactForRecord(nest(credential, layers), credential);
      outcomes.push({
        layers,
        sighted: scan(credential, out).length,
        marked: out.includes(RECORD_REDACTION),
      });
      expected.push({ layers, sighted: 0, marked: layers <= MAX_PARSE_DEPTH + 1 });
    }
    expect(outcomes).toEqual(expected);
  });
});

/** `inner` under `layers` JSON escape layers, each one more JSON.parse away. */
function nest(inner: string, layers: number): string {
  return new Array<null>(layers).fill(null).reduce((out) => JSON.stringify({ next: out }), inner);
}
