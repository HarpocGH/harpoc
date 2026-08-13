import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Permission } from "@harpoc/shared";
import { createHarnessVault, PREREGISTRATION_FILE } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { loadExpectations } from "./evidence/preregistration.js";
import type { EvidenceRecord } from "./evidence/record.js";
import { assertFleetUp } from "./harness/backends.js";
import { recordArm } from "./harness/evidence.js";
import { startBaselineArm } from "./arms/baseline.js";
import { startHarpocArm } from "./arms/harpoc.js";
import type { Arm } from "./arms/arm.js";
import { SCENARIO_ARMS } from "./scenarios/index.js";
import type { ScenarioSetup } from "./scenarios/scenario.js";

/**
 * The §6.2 attack scenarios, in two arms (C-3).
 *
 * Every arm runs the SAME payload against the §2.3 status quo and against
 * Harpoc, on the same harness, with only the credential-handling layer
 * differing. That converts each subsection from an assertion ("blocked with
 * Harpoc") into a controlled comparison with a visible effect: the baseline
 * leaks, Harpoc does not.
 *
 * Both arms are driven through a real MCP client over Streamable HTTP; the
 * Harpoc side carries a scoped, vault-signed Bearer token (C-2), because under
 * a tokenless launch most of the authorization machinery under evaluation is
 * inert and the run would say nothing about the deployed posture.
 *
 * Outcomes are compared against `preregistration.json`, committed BEFORE the
 * run (C-4). Six arms are pre-registered as BYPASSED: those are the honest
 * residuals the chapter commits to reporting, not failures.
 */
const PASSWORD = "e2e-scenarios-pw";

/**
 * The §6.2 subsections this suite owns, as a literal.
 *
 * Deliberately NOT derived from `SCENARIO_ARMS`: deriving it would make a
 * deleted arm undetectable, because the registry and the check would shrink
 * together and the coverage assertion would pass over an empty set. Adding a
 * scenario means editing this list too, and that friction is the point.
 */
const PHASE4_SCENARIOS: string[] = [
  "prompt-injection",
  "url-manipulation",
  "shadow-escape",
  "output-channel-leakage",
  "response-channel-echo",
];

describe("attack scenarios — baseline versus Harpoc", () => {
  let vault: HarnessVault;
  let harpoc: Arm;
  const setups = new Map<string, ScenarioSetup>();
  const emitted: EvidenceRecord[] = [];

  const keyOf = (s: { scenario: string; variant?: string }): string =>
    `${s.scenario}|${s.variant ?? ""}`;

  beforeAll(async () => {
    for (const service of new Set(SCENARIO_ARMS.flatMap((a) => a.services ?? []))) {
      assertFleetUp(service);
    }

    vault = await createHarnessVault(PASSWORD);
    for (const arm of SCENARIO_ARMS) {
      setups.set(keyOf(arm), await arm.setup(vault));
    }

    harpoc = await startHarpocArm(vault, "scenario-principal", [
      Permission.READ,
      Permission.USE,
      Permission.LIST,
    ]);
  }, 300_000);

  afterAll(async () => {
    for (const setup of setups.values()) await setup.cleanup?.();
    await harpoc?.close();
    await vault?.destroy();
  });

  for (const scenarioArm of SCENARIO_ARMS) {
    const label = scenarioArm.variant
      ? `${scenarioArm.scenario} / ${scenarioArm.variant}`
      : scenarioArm.scenario;

    describe(label, () => {
      for (const armName of ["baseline", "harpoc"] as const) {
        it(`${armName}: matches its pre-registered outcome`, async () => {
          const setup = setups.get(keyOf(scenarioArm));
          if (setup === undefined) throw new Error(`no setup for ${label}`);

          // The baseline server holds ONE credential in its launch environment
          // (Listing 2.1), so it is started per arm with that arm's own value —
          // a shared instance would answer every scenario with the first
          // scenario's credential and quietly mis-measure all the others.
          const perArmBaseline =
            armName === "baseline" ? await startBaselineArm(setup.credential) : undefined;
          let observed: string;
          try {
            observed = await scenarioArm.observe(perArmBaseline ?? harpoc, setup);
          } finally {
            await perArmBaseline?.close();
          }

          const record = recordArm(
            {
              scenario: scenarioArm.scenario,
              context: scenarioArm.context,
              variant: scenarioArm.variant,
              surface: "mcp-http",
              interface: "mcp",
              arm: armName,
            },
            observed,
          );
          emitted.push(record);

          // A divergence is a finding to report, not an expectation to edit —
          // git history is the control on that.
          expect(
            record.match,
            `${label} [${armName}]: expected ${record.expected}, observed ${record.observed}`,
          ).toBe(true);
        }, 180_000);
      }
    });
  }

  /**
   * Coverage, asserted rather than assumed — the Phase 3 review's lesson. A
   * deleted arm shrinks the evidence silently otherwise, and pre-registration
   * cannot notice: it errors on an UNREGISTERED key, never on a registered
   * expectation that nothing exercised.
   */
  it("runs every pre-registered scenario arm, in both arms", () => {
    expect(emitted).toHaveLength(SCENARIO_ARMS.length * 2);
    expect(emitted.every((r) => r.match)).toBe(true);

    const registered = loadExpectations(PREREGISTRATION_FILE).filter((e) =>
      PHASE4_SCENARIOS.includes(e.scenario),
    );
    expect(registered.length).toBeGreaterThan(0);
    const ran = new Set(emitted.map((r) => `${r.scenario}|${r.variant ?? ""}|${r.arm}`));
    const missing = registered
      .map((e) => `${e.scenario}|${e.variant ?? ""}|${e.arm}`)
      .filter((k) => !ran.has(k));
    expect(missing).toEqual([]);

    // Every scenario carries BOTH arms: a paired table with a missing baseline
    // cell is the failure mode C-3 exists to prevent.
    for (const arm of SCENARIO_ARMS) {
      const arms = emitted
        .filter((r) => r.scenario === arm.scenario && (r.variant ?? "") === (arm.variant ?? ""))
        .map((r) => r.arm)
        .sort();
      expect(arms).toEqual(["baseline", "harpoc"]);
    }
  });
});
