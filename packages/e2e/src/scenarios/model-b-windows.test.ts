import { describe, expect, it } from "vitest";
import { HELD_OUTCOMES, LEAKED_OUTCOMES } from "../../scripts/recheck.mjs";
import { PREREGISTRATION_FILE_B } from "../evidence/paths.js";
import { PREREGISTRATION_FILE_B_WINDOWS } from "../evidence/paths-windows.js";
import {
  expectationFor,
  loadExpectations,
  validateExpectationSet,
} from "../evidence/preregistration.js";
import { MODEL_B_WINDOWS_SCENARIOS } from "./model-b-windows.js";

/**
 * The Windows ids (RE-B7-3 as ruled) as a literal: a list derived from the
 * table would shrink with it (the `PHASE4_SCENARIOS` lesson).
 */
const WINDOWS_IDS = [
  "b-win-headless-dpapi",
  "b-win-two-account-value-route",
  "b-win-two-account-vault-dir",
  "b-win-agent-pipe-exposure",
  "b-win-two-account-inventory",
  "b-win-negative-same-account",
];

describe("the model-B Windows scenario table and its pre-registration", () => {
  const expectations = loadExpectations(PREREGISTRATION_FILE_B_WINDOWS);

  it("holds the set invariants: no duplicate key, no OS-keyed orphan, no half comparison", () => {
    expect(validateExpectationSet(expectations)).toEqual([]);
  });

  it("registers exactly the six Windows ids, and shares none with the Linux file", () => {
    expect(expectations.map((e) => e.scenario).sort()).toEqual([...WINDOWS_IDS].sort());
    const linux = new Set(loadExpectations(PREREGISTRATION_FILE_B).map((e) => e.scenario));
    expect(expectations.filter((e) => linux.has(e.scenario))).toEqual([]);
  });

  it("gives every scenario of the table exactly one expectation, the outcome the table states", () => {
    for (const row of MODEL_B_WINDOWS_SCENARIOS) {
      const key = {
        scenario: row.scenario,
        context: row.context,
        surface: row.surface,
        arm: "harpoc" as const,
      };
      expect(
        expectations.filter((e) => e.scenario === row.scenario),
        row.scenario,
      ).toHaveLength(1);
      expect(expectationFor(expectations, key), row.scenario).toBe(row.expected);
    }
  });

  it("gives every expectation a scenario of the table, and the table no id twice", () => {
    const ids = new Set(MODEL_B_WINDOWS_SCENARIOS.map((r) => r.scenario));
    expect(ids.size).toBe(MODEL_B_WINDOWS_SCENARIOS.length);
    expect(expectations.filter((e) => !ids.has(e.scenario)).map((e) => e.scenario)).toEqual([]);
  });

  it("registers Harpoc rows only, with no variant and no OS key", () => {
    expect(
      expectations.every(
        (e) => e.arm === "harpoc" && e.variant === undefined && e.host_os === undefined,
      ),
    ).toBe(true);
  });

  it("pre-registers only outcomes the re-check judges, so recheck --require-calls covers every record", () => {
    const judged: readonly string[] = [...HELD_OUTCOMES, ...LEAKED_OUTCOMES, "BYPASSED"];
    for (const e of expectations) expect(judged, e.scenario).toContain(e.expected);
  });

  it("runs the control on the harness's own child and every other row on the deployment", () => {
    expect(
      MODEL_B_WINDOWS_SCENARIOS.filter((r) => r.surface === "process").map((r) => r.scenario),
    ).toEqual(["b-win-negative-same-account"]);
  });

  it("keys each record's interface to the audit interface its rows are verified against", () => {
    expect(
      Object.fromEntries(MODEL_B_WINDOWS_SCENARIOS.map((r) => [r.scenario, r.interface])),
    ).toEqual({
      "b-win-headless-dpapi": "rest",
      "b-win-two-account-value-route": "rest",
      "b-win-two-account-vault-dir": "filesystem",
      "b-win-agent-pipe-exposure": "ssh_agent",
      "b-win-two-account-inventory": "proxy+ssh_agent",
      "b-win-negative-same-account": "process-inventory",
    });
  });
});
