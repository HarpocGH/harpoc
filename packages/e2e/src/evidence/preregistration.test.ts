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
    expect(problems.join("\n")).toMatch(/both arms/i);
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
