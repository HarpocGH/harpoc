import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { loadExpectations, expectationFor } from "./preregistration.js";
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
