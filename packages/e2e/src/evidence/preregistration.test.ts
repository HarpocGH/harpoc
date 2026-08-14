import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { loadExpectations, expectationFor, validateExpectationSet } from "./preregistration.js";
import type { Expectation } from "./preregistration.js";

const ROWS: Expectation[] = [
  {
    scenario: "database-happy-path",
    context: "database",
    surface: "mcp-http",
    arm: "harpoc",
    expected: "SUCCEEDED",
  },
];

describe("pre-registration", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-prereg-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads expectations from disk", () => {
    const file = join(dir, "p.json");
    writeFileSync(file, JSON.stringify(ROWS), "utf8");
    expect(loadExpectations(file)).toHaveLength(1);
  });

  it("rejects a malformed row rather than guessing", () => {
    const file = join(dir, "bad.json");
    writeFileSync(file, JSON.stringify([{ scenario: "x" }]), "utf8");
    expect(() => loadExpectations(file)).toThrow(/malformed/i);
  });

  it("rejects a file that is not an array", () => {
    const file = join(dir, "obj.json");
    writeFileSync(file, JSON.stringify({ scenario: "x" }), "utf8");
    expect(() => loadExpectations(file)).toThrow(/malformed/i);
  });

  it("returns the registered expectation", () => {
    expect(
      expectationFor(ROWS, {
        scenario: "database-happy-path",
        context: "database",
        surface: "mcp-http",
        arm: "harpoc",
      }),
    ).toBe("SUCCEEDED");
  });

  it("throws for an unregistered combination", () => {
    expect(() =>
      expectationFor(ROWS, {
        scenario: "database-happy-path",
        context: "database",
        surface: "rest",
        arm: "harpoc",
      }),
    ).toThrow(/not pre-registered/i);
  });

  it("keeps the committed pre-registration file loadable", () => {
    // fileURLToPath, never URL.pathname: the latter yields "/C:/..." on
    // Windows, which readFileSync resolves to "C:\C:\...".
    const committed = fileURLToPath(new URL("../../preregistration.json", import.meta.url));
    expect(loadExpectations(committed).length).toBeGreaterThan(0);
  });
});

/**
 * `variant` exists because a scenario's arms are not distinguishable by
 * scenario+context+surface+arm alone: output-channel leakage runs ten arms that
 * agree on all four. Without it they collide onto one key, and nine of the ten
 * silently read a tenth's expectation.
 */
describe("pre-registration variants", () => {
  const VARIANTS: Expectation[] = [
    {
      scenario: "output-channel-leakage",
      context: "process",
      variant: "naive-echo",
      surface: "mcp-http",
      arm: "harpoc",
      expected: "BLOCKED",
    },
    {
      scenario: "output-channel-leakage",
      context: "process",
      variant: "chunking",
      surface: "mcp-http",
      arm: "harpoc",
      expected: "BYPASSED",
    },
  ];

  it("distinguishes two arms that differ only by variant", () => {
    const base = {
      scenario: "output-channel-leakage",
      context: "process",
      surface: "mcp-http",
      arm: "harpoc",
    } as const;
    expect(expectationFor(VARIANTS, { ...base, variant: "naive-echo" })).toBe("BLOCKED");
    expect(expectationFor(VARIANTS, { ...base, variant: "chunking" })).toBe("BYPASSED");
  });

  it("treats an absent variant as its own key rather than a wildcard", () => {
    expect(() =>
      expectationFor(VARIANTS, {
        scenario: "output-channel-leakage",
        context: "process",
        surface: "mcp-http",
        arm: "harpoc",
      }),
    ).toThrow(/not pre-registered/i);
  });

  it("keeps variant-less keys byte-stable, so the pre-Phase-4 rows still resolve", () => {
    expect(
      expectationFor(ROWS, {
        scenario: "database-happy-path",
        context: "database",
        surface: "mcp-http",
        arm: "harpoc",
      }),
    ).toBe("SUCCEEDED");
  });
});

/**
 * R-1 obligation 2: outcomes must match across operating systems, and a
 * divergence is permitted only where the platform behaviour IS the designed
 * outcome — never as a skip. Network isolation is the first such case: it
 * refuses with NETWORK_ISOLATION_UNAVAILABLE on Windows by design.
 */
describe("pre-registration OS keying", () => {
  const OS_KEYED: Expectation[] = [
    {
      scenario: "output-channel-leakage",
      context: "process",
      variant: "network-isolation",
      surface: "mcp-http",
      arm: "harpoc",
      expected: "BLOCKED",
    },
    {
      scenario: "output-channel-leakage",
      context: "process",
      variant: "network-isolation",
      surface: "mcp-http",
      arm: "harpoc",
      host_os: "win32",
      expected: "REFUSED_UNAVAILABLE",
    },
  ];

  const KEY = {
    scenario: "output-channel-leakage",
    context: "process",
    variant: "network-isolation",
    surface: "mcp-http",
    arm: "harpoc",
  } as const;

  it("prefers the row keyed to the running OS", () => {
    expect(expectationFor(OS_KEYED, KEY, "win32")).toBe("REFUSED_UNAVAILABLE");
  });

  it("falls back to the OS-agnostic row when no OS-keyed row matches", () => {
    expect(expectationFor(OS_KEYED, KEY, "linux")).toBe("BLOCKED");
  });

  it("prefers the OS-keyed row regardless of its position in the file", () => {
    expect(expectationFor([...OS_KEYED].reverse(), KEY, "win32")).toBe("REFUSED_UNAVAILABLE");
  });

  it("rejects a non-string host_os rather than ignoring it", () => {
    const file = join(dirForOsTest(), "os.json");
    writeFileSync(file, JSON.stringify([{ ...OS_KEYED[0], host_os: 7 }]), "utf8");
    expect(() => loadExpectations(file)).toThrow(/malformed/i);
  });
});

function dirForOsTest(): string {
  return mkdtempSync(join(tmpdir(), "harpoc-prereg-os-"));
}

/**
 * Invariants of the pre-registration SET, as opposed to a single row.
 *
 * Each of these fails silently rather than loudly, which is why they are worth
 * asserting: a corrupted expectation set still produces a green run and a
 * plausible-looking table.
 */
describe("pre-registration set invariants", () => {
  const row = (over: Partial<Expectation>): Expectation => ({
    scenario: "s",
    context: "http",
    surface: "mcp-http",
    arm: "harpoc",
    expected: "BLOCKED",
    ...over,
  });

  it("reports duplicate keys — `find` would silently use the first", () => {
    // Two rows, same key, different outcomes: the second is dead, so a real
    // divergence could be masked by whichever happens to be written first.
    const problems = validateExpectationSet([
      row({ variant: "v", arm: "baseline", expected: "LEAKED" }),
      row({ variant: "v", arm: "baseline", expected: "EXFILTRATED" }),
      row({ variant: "v", arm: "harpoc" }),
    ]);
    expect(problems.join("\n")).toMatch(/duplicate/i);
  });

  it("reports an OS-keyed row with no OS-agnostic sibling", () => {
    // Otherwise every OTHER platform throws "not pre-registered" mid-run, and
    // the arm has an expectation on exactly one OS — which is the opposite of
    // R-1's "outcomes must match across operating systems".
    const problems = validateExpectationSet([
      row({ variant: "v", arm: "baseline", expected: "LEAKED" }),
      row({ variant: "v", arm: "harpoc", host_os: "win32", expected: "REFUSED_UNAVAILABLE" }),
    ]);
    expect(problems.join("\n")).toMatch(/os-keyed/i);
  });

  it("reports a scenario arm missing its pair", () => {
    // A paired table with a missing baseline cell is exactly the failure mode
    // C-3 exists to prevent.
    const problems = validateExpectationSet([row({ variant: "v", arm: "harpoc" })]);
    expect(problems.join("\n")).toMatch(/no baseline counterpart/i);
  });

  it("accepts a well-formed set, OS-keyed override included", () => {
    expect(
      validateExpectationSet([
        row({ variant: "v", arm: "baseline", expected: "LEAKED" }),
        row({ variant: "v", arm: "harpoc" }),
        row({ variant: "v", arm: "harpoc", host_os: "win32", expected: "REFUSED_UNAVAILABLE" }),
      ]),
    ).toEqual([]);
  });

  it("holds for the committed pre-registration file", () => {
    const committed = fileURLToPath(new URL("../../preregistration.json", import.meta.url));
    expect(validateExpectationSet(loadExpectations(committed))).toEqual([]);
  });
});

/**
 * F13: the both-arms check used to `continue` on `variant === undefined`, so
 * the six variant-less Phase 4B counterpart baselines were covered only by a
 * hardcoded array in the runner — a new variant-less baseline-only
 * counterpart forgotten from that array would slip past everything.
 *
 * The rule is asymmetric on purpose: every baseline row needs a Harpoc
 * counterpart regardless of variant (a baseline is only ever half of a
 * comparison), but the reverse direction stays scoped to variant-bearing
 * rows, because the 47 variant-less Harpoc rows are single-arm demonstration
 * cells by construction and predate C-3.
 */
describe("pre-registration pairing — variant-less baselines (F13)", () => {
  it("flags a variant-less baseline with no harpoc counterpart", () => {
    const problems = validateExpectationSet([
      {
        scenario: "new-counterpart",
        context: "git",
        surface: "mcp-http",
        arm: "baseline",
        expected: "SUCCEEDED",
      },
    ]);
    expect(problems.some((p) => p.includes("new-counterpart"))).toBe(true);
  });

  it("accepts a variant-less baseline that has one (negative control)", () => {
    const problems = validateExpectationSet([
      {
        scenario: "new-counterpart",
        context: "git",
        surface: "mcp-http",
        arm: "baseline",
        expected: "SUCCEEDED",
      },
      {
        scenario: "new-counterpart",
        context: "git",
        surface: "mcp-http",
        arm: "harpoc",
        expected: "BLOCKED",
      },
    ]);
    expect(problems).toEqual([]);
  });

  it("does not flag the 47 single-arm demonstration rows (negative control)", () => {
    // Passes trivially under both the pre-fix and the fixed key (a lone
    // variant-less harpoc row is out of scope for either direction). Kept
    // anyway: it is the guard against a naive FULLY-symmetric implementation
    // that would flag every variant-less Harpoc row and make the validator
    // useless against the real file.
    const problems = validateExpectationSet([
      {
        scenario: "demo-http",
        context: "http",
        surface: "rest",
        arm: "harpoc",
        expected: "OPAQUE",
      },
    ]);
    expect(problems).toEqual([]);
  });

  // "keeps the real pre-registration clean" intentionally not repeated here —
  // it is byte-for-byte the same code path as
  // "holds for the committed pre-registration file" above (round-1 review,
  // minor 2); that test already covers this describe block's fix.

  /**
   * Round-1 review finding (Critical): `pairKey` without `variant` lets ONE
   * variant's baseline vouch for every sibling variant sharing
   * scenario+context+surface — the real file has three such families
   * (url-manipulation/http/mcp-http: 3 variants, output-channel-leakage/
   * process/mcp-http: 11, response-channel-echo/http/mcp-http: 8). A
   * variant-bearing Harpoc row with no baseline of its own would be masked by
   * an unrelated sibling's baseline — the same silent-pass shape as F13
   * itself. This pins the fix: variant B must be flagged even though variant
   * A (same scenario+context+surface) is fully paired.
   */
  it("flags a variant-bearing harpoc row masked by a sibling variant's baseline (round-1 review)", () => {
    const problems = validateExpectationSet([
      {
        scenario: "output-channel-leakage",
        context: "process",
        variant: "variant-a",
        surface: "mcp-http",
        arm: "baseline",
        expected: "LEAKED",
      },
      {
        scenario: "output-channel-leakage",
        context: "process",
        variant: "variant-a",
        surface: "mcp-http",
        arm: "harpoc",
        expected: "BLOCKED",
      },
      {
        scenario: "output-channel-leakage",
        context: "process",
        variant: "variant-b",
        surface: "mcp-http",
        arm: "harpoc",
        expected: "BLOCKED",
      },
    ]);
    expect(
      problems.some((p) => p.includes("variant-b") && p.includes("no baseline counterpart")),
    ).toBe(true);
  });
});
