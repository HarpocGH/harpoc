import { describe, it, expect } from "vitest";
import { sightings } from "./opacity.js";

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
import { assertOpaque, assertPresent } from "./opacity.js";
import { serializeError } from "./serialize-error.js";

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
