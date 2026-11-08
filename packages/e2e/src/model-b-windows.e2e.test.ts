import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PREREGISTRATION_FILE_B_WINDOWS } from "./evidence/paths-windows.js";
import { loadExpectations } from "./evidence/preregistration.js";
import type { EvidenceRecord } from "./evidence/record.js";
import { recordModelBWindows, resetWindowsEvidence } from "./harness/evidence-windows.js";
import { resolveCliEntry } from "./harness/fixtures.js";
import { launchFailure, runAsWindows, systemPaths } from "./harness/runas-windows.js";
import { assertTierAvailable } from "./harness/tiers.js";
import {
  cliArgv,
  defaultRuntimeDirWindows,
  startTwoAccountDeployment,
} from "./harness/two-identity-windows.js";
import type { TwoAccountDeployment } from "./harness/two-identity-windows.js";
import {
  MODEL_B_WINDOWS_SCENARIOS,
  NEGATIVE_CONTROL_VALUE_WINDOWS,
  captureCalls,
} from "./scenarios/model-b-windows.js";
import { win32 } from "node:path";

/**
 * Deployment model B on Windows (tranche B7): the built CLI daemon as the vault
 * account — headless from a DPAPI-sealed key, memory mode — and the agent
 * account's own programs driving REST, the proxy's loopback listener and the
 * agent pipe; the control is the harness's own marked child, whose command line
 * the same listing carries. Outcomes are compared against
 * `preregistration-model-b-windows.json`, committed before the run (DB-15), and
 * every record goes to `evidence/run-b-windows.jsonl` with the calls it was
 * judged on.
 *
 * Windows only: local accounts, `ProcessStartInfo`'s `UserName`, DPAPI and the
 * `Win32_Process` listing. The accounts come from HARPOC_TWO_USER_VAULT_USER,
 * HARPOC_TWO_USER_AGENT_USER and their two passwords
 * HARPOC_TWO_USER_VAULT_PASSWORD and HARPOC_TWO_USER_AGENT_PASSWORD (the job
 * exports them masked), the runtime directory from HARPOC_TWO_USER_RUNTIME_DIR
 * (`%ProgramData%\harpoc\run` by default); where the `two-account-windows` tier
 * of HARPOC_REQUIRE_PLATFORM_TESTS is required a missing account, CLI, curl or
 * ssh fails instead of skipping.
 */
const VAULT_USER = process.env["HARPOC_TWO_USER_VAULT_USER"];
const AGENT_USER = process.env["HARPOC_TWO_USER_AGENT_USER"];
const VAULT_PASSWORD = process.env["HARPOC_TWO_USER_VAULT_PASSWORD"];
const AGENT_PASSWORD = process.env["HARPOC_TWO_USER_AGENT_PASSWORD"];
const MASTER_PASSWORD = "b7-model-b-master-pw-1";
const API_KEY_VALUE = "b7-model-b-api-key-value-2f6a";

const MODEL_B_WINDOWS_SCENARIO_IDS = [
  "b-win-headless-dpapi",
  "b-win-two-account-value-route",
  "b-win-two-account-vault-dir",
  "b-win-agent-pipe-exposure",
  "b-win-two-account-inventory",
  "b-win-negative-same-account",
];

describe.skipIf(process.platform !== "win32")(
  "deployment model B on Windows — the two-account evidence (Windows only: local accounts, DPAPI, Win32_Process)",
  () => {
    let available = false;
    let deployment: TwoAccountDeployment | undefined;
    const emitted: EvidenceRecord[] = [];

    beforeAll(async () => {
      resetWindowsEvidence();
      let probeError: unknown;
      try {
        if (
          VAULT_USER === undefined ||
          AGENT_USER === undefined ||
          VAULT_PASSWORD === undefined ||
          AGENT_PASSWORD === undefined
        ) {
          throw new Error(
            "HARPOC_TWO_USER_VAULT_USER, HARPOC_TWO_USER_AGENT_USER and the two passwords are not set",
          );
        }
        const accounts = [
          { user: VAULT_USER, password: VAULT_PASSWORD },
          { user: AGENT_USER, password: AGENT_PASSWORD },
        ];
        for (const account of accounts) {
          const probe = await runAsWindows(account, cliArgv(resolveCliEntry(), ["--version"]));
          if (probe.code !== 0) {
            throw new Error(
              `${account.user} cannot run the built CLI (exit ${String(probe.code)}, Win32 error ${String(launchFailure(probe))})`,
            );
          }
        }
        const tools = systemPaths();
        for (const tool of [
          [tools.ssh, "-V"],
          [tools.curl, "--version"],
        ] as const) {
          const probe = await runAsWindows(accounts[1] as (typeof accounts)[number], [...tool]);
          if (probe.code !== 0) {
            throw new Error(`the agent account cannot run ${win32.basename(tool[0])}`);
          }
          if (tool[0] === tools.ssh && !probe.stderr.includes("OpenSSH_for_Windows")) {
            throw new Error("the agent's ssh is not the native Windows client");
          }
        }
        available = true;
      } catch (err) {
        probeError = err;
      }
      assertTierAvailable("two-account-windows", available, probeError);
      if (!available) return;

      const programData = process.env["ProgramData"] as string;
      deployment = await startTwoAccountDeployment({
        vault: { user: VAULT_USER as string, password: VAULT_PASSWORD as string },
        agent: { user: AGENT_USER as string, password: AGENT_PASSWORD as string },
        runtimeDir: process.env["HARPOC_TWO_USER_RUNTIME_DIR"] ?? defaultRuntimeDirWindows(),
        vaultRoot: win32.join(programData, "harpoc", "vault"),
        publicRoot: win32.join(programData, "harpoc-b7-public"),
        password: MASTER_PASSWORD,
        apiKeyValue: API_KEY_VALUE,
      });
    }, 300_000);

    afterAll(async () => {
      await deployment?.stop();
    }, 120_000);

    for (const row of MODEL_B_WINDOWS_SCENARIOS) {
      it(`${row.scenario}: matches its pre-registered outcome`, async (ctx) => {
        if (!available) {
          return ctx.skip("the two-account-windows tier is unavailable and not required here");
        }
        const d = deployment as TwoAccountDeployment;
        const capture = captureCalls(
          ...d.credentials.all,
          NEGATIVE_CONTROL_VALUE_WINDOWS,
          MASTER_PASSWORD,
          VAULT_PASSWORD as string,
          AGENT_PASSWORD as string,
        );
        const observed = await row.observe(d, capture);
        const calls = capture.calls();
        const token = await d.agentToken();
        expect(JSON.stringify(calls).includes(token)).toBe(false);
        const record = recordModelBWindows(
          {
            scenario: row.scenario,
            context: row.context,
            surface: row.surface,
            interface: row.interface,
            arm: "harpoc",
          },
          observed,
          calls,
        );
        emitted.push(record);
        expect(
          record.match,
          `${row.scenario}: expected ${record.expected}, observed ${record.observed}`,
        ).toBe(true);
      }, 180_000);
    }

    it("runs every pre-registered Windows scenario", (ctx) => {
      if (!available) {
        return ctx.skip("the two-account-windows tier is unavailable and not required here");
      }
      const registered = loadExpectations(PREREGISTRATION_FILE_B_WINDOWS);
      expect(registered.map((e) => e.scenario).sort()).toEqual(
        [...MODEL_B_WINDOWS_SCENARIO_IDS].sort(),
      );
      const ran = new Set(emitted.map((r) => r.scenario));
      expect(registered.filter((e) => !ran.has(e.scenario)).map((e) => e.scenario)).toEqual([]);
      expect(emitted).toHaveLength(MODEL_B_WINDOWS_SCENARIOS.length);
      expect(emitted.every((r) => r.match)).toBe(true);
    });
  },
);
