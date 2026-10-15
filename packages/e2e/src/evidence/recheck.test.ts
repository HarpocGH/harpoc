import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { RECORD_REDACTION } from "../assert/opacity.js";
import {
  HELD_OUTCOMES,
  LEAKED_OUTCOMES,
  LEAK_NOT_MARKABLE,
  RECORD_MARKER,
  leakKeyOf,
  recheck,
  renderRecheck,
} from "../../scripts/recheck.mjs";
import type { RecheckRecord } from "../../scripts/recheck.mjs";

const PREREGISTRATION = join(dirname(fileURLToPath(import.meta.url)), "../../preregistration.json");

function record(over: Partial<RecheckRecord>): RecheckRecord {
  return {
    scenario: "output-channel-leakage",
    context: "process",
    variant: "naive-echo",
    surface: "mcp-http",
    arm: "harpoc",
    observed: "BLOCKED",
    calls: [{ ok: true, text: '{"stdout":"[REDACTED]\\nmarker"}' }],
    ...over,
  };
}

const CLEAN = { total: 0, checked: 0, unchecked: 0, partial: 0, inconsistent: [] };

/**
 * The re-check over committed evidence (test-review-2026-10-09 I1): what a
 * record's `calls` must agree with, judged from the record alone. Written
 * against synthetic records — a committed pair is designed never to reach the
 * inconsistent states.
 */
describe("recheck", () => {
  it("names the record-time marker the capture layer writes", () => {
    expect(RECORD_MARKER).toBe(RECORD_REDACTION);
  });

  it("passes a consistent set and counts what it could and could not check", () => {
    const out = recheck([
      record({}),
      record({
        arm: "baseline",
        observed: "LEAKED",
        calls: [{ ok: true, text: `x ${RECORD_MARKER}` }],
      }),
      record({ scenario: "demo-http", observed: "SUCCEEDED", calls: [{ ok: true, text: "{}" }] }),
      record({ scenario: "machinery-selfcheck", observed: "OPAQUE", calls: undefined }),
    ]);
    expect(out).toEqual({ ...CLEAN, total: 4, checked: 3, unchecked: 1 });
  });

  it("flags a held Harpoc verdict whose calls carry the credential marker", () => {
    for (const observed of HELD_OUTCOMES) {
      const out = recheck([
        record({ observed, calls: [{ ok: true, text: `{"stdout":"${RECORD_MARKER}"}` }] }),
      ]);
      expect(out.inconsistent, observed).toHaveLength(1);
      expect(out.inconsistent[0]?.reason).toMatch(/credential marker/);
    }
  });

  it("finds the marker in the error and stderr fields too", () => {
    const inError = recheck([record({ calls: [{ ok: false, text: "", error: RECORD_MARKER }] })]);
    const inStderr = recheck([record({ calls: [{ ok: true, text: "", stderr: RECORD_MARKER }] })]);
    expect(inError.inconsistent).toHaveLength(1);
    expect(inStderr.inconsistent).toHaveLength(1);
  });

  it("flags a LEAKED or CREDENTIAL_CAPTURED verdict whose calls never show the credential", () => {
    // The two named here, not read from the module: log-to-leak's captured log is
    // built from the recorded calls, so its CREDENTIAL_CAPTURED is call-borne too.
    expect([...LEAKED_OUTCOMES]).toEqual(["LEAKED", "CREDENTIAL_CAPTURED"]);
    for (const observed of ["LEAKED", "CREDENTIAL_CAPTURED"]) {
      const out = recheck([
        record({ arm: "baseline", observed, calls: [{ ok: true, text: "clean" }] }),
      ]);
      expect(out.inconsistent, observed).toHaveLength(1);
      expect(out.inconsistent[0]?.reason).toContain(observed);
    }
  });

  it("exempts the baseline leaks the marker cannot show — a fragment or a file, not the call text", () => {
    const chunking = record({
      variant: "chunking",
      arm: "baseline",
      observed: "LEAKED",
      calls: [{ ok: true, text: '{"stdout":"p\\n4\\n-\\nc\\nr\\ne\\nd"}' }],
    });
    const partial = record({
      scenario: "response-channel-echo",
      context: "http",
      variant: "partial-last4",
      arm: "baseline",
      observed: "LEAKED",
      calls: [{ ok: true, text: '{"body":"...tail"}' }],
    });
    expect(recheck([chunking, partial])).toEqual({ ...CLEAN, total: 2, checked: 2 });
  });

  it("names exactly the pre-registered baseline LEAKED arms whose leak is a fragment or off the call text", () => {
    const expectations = JSON.parse(readFileSync(PREREGISTRATION, "utf8")) as Array<{
      scenario: string;
      context: string;
      variant?: string;
      arm: string;
      expected: string;
    }>;
    const baselineLeaks = new Set(
      expectations
        .filter((e) => e.arm === "baseline" && e.expected === "LEAKED")
        .map((e) => leakKeyOf(e)),
    );
    expect(LEAK_NOT_MARKABLE).toHaveLength(8);
    for (const key of LEAK_NOT_MARKABLE) expect(baselineLeaks.has(key), key).toBe(true);
    expect(new Set(LEAK_NOT_MARKABLE).size).toBe(LEAK_NOT_MARKABLE.length);
  });

  it("still holds a Harpoc arm on an exempt key to the held rule", () => {
    const out = recheck([
      record({
        variant: "chunking",
        observed: "BLOCKED",
        calls: [{ ok: true, text: `{"stdout":"${RECORD_MARKER}"}` }],
      }),
    ]);
    expect(out.inconsistent).toHaveLength(1);
  });

  it("flags a SUCCEEDED verdict with no completed call", () => {
    const out = recheck([
      record({ scenario: "demo-http", observed: "SUCCEEDED", calls: [{ ok: false, text: "" }] }),
    ]);
    expect(out.inconsistent).toHaveLength(1);
    expect(out.inconsistent[0]?.reason).toMatch(/SUCCEEDED/);
  });

  it("leaves the off-record verdicts alone — EXFILTRATED's proof is the sink, BYPASSED's a partial reveal", () => {
    const out = recheck([
      record({ arm: "baseline", observed: "EXFILTRATED", calls: [{ ok: true, text: "clean" }] }),
      record({ arm: "baseline", observed: "BYPASSED", calls: [{ ok: true, text: "fragment" }] }),
    ]);
    expect(out.inconsistent).toEqual([]);
    expect(out.checked).toBe(2);
  });

  it("counts a record with a truncated or elided call as partial and still judges what it carries", () => {
    const truncated = record({ calls: [{ ok: true, text: "[REDACTED] prefix", truncated: true }] });
    const elided = record({ calls: [{ ok: true, text: RECORD_MARKER, elided: true }] });
    const out = recheck([truncated, elided]);
    expect(out.partial).toBe(2);
    expect(out.checked).toBe(2);
    expect(out.inconsistent).toHaveLength(1);
    expect(out.inconsistent[0]?.reason).toMatch(/credential marker/);
  });

  it("keys an inconsistency by the record's pre-registration key", () => {
    const out = recheck([
      record({ arm: "baseline", observed: "LEAKED", calls: [{ ok: true, text: "clean" }] }),
    ]);
    expect(out.inconsistent[0]?.key).toBe(
      "output-channel-leakage|process|naive-echo|mcp-http|baseline",
    );
  });

  it("renders the summary and every inconsistency", () => {
    const out = recheck([
      record({}),
      record({ calls: [{ ok: true, text: "cut", truncated: true }] }),
      record({ arm: "baseline", observed: "LEAKED", calls: [{ ok: true, text: "clean" }] }),
    ]);
    const text = renderRecheck(out);
    expect(text).toContain(
      "3 record(s), 3 re-checkable, 0 without calls, 1 partial (truncated or elided), 1 inconsistent",
    );
    expect(text).toContain("output-channel-leakage|process|naive-echo|mcp-http|baseline");
  });
});
