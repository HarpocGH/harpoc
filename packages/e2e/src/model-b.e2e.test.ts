import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PREREGISTRATION_FILE_B } from "./evidence/paths.js";
import { loadExpectations } from "./evidence/preregistration.js";
import type { EvidenceRecord } from "./evidence/record.js";
import { recordModelB } from "./harness/evidence.js";
import { resolveCliEntry } from "./harness/fixtures.js";
import { runAs } from "./harness/sudo.js";
import { assertTierAvailable } from "./harness/tiers.js";
import { DEFAULT_RUNTIME_DIR, startTwoIdentityDeployment } from "./harness/two-identity.js";
import type { TwoIdentityDeployment } from "./harness/two-identity.js";
import {
  MODEL_B_DOCKER_IMAGE,
  MODEL_B_SCENARIOS,
  NEGATIVE_CONTROL_VALUE,
  captureCalls,
} from "./scenarios/model-b.js";

/**
 * Deployment model B's evidence (design § 6 ch6 rows, tranche B6): the built
 * CLI daemon as the vault user — headless, memory mode, a fake
 * `$CREDENTIALS_DIRECTORY` — and the agent user's own curl, ssh and container
 * driving REST, the egress proxy and the agent socket; the negative control is
 * model A in process. Outcomes are compared against
 * `preregistration-model-b.json`, committed before the run (DB-15), and every
 * record goes to `evidence/run-b.jsonl` with the calls it was judged on.
 *
 * Linux only: `sudo -n -u`, `/proc/<pid>/environ` and POSIX ownership. The
 * users come from HARPOC_TWO_UID_VAULT_USER and HARPOC_TWO_UID_AGENT_USER, the
 * runtime directory from HARPOC_TWO_UID_RUNTIME_DIR (the recipe's /run/harpoc
 * by default); where the `two-uid` tier of HARPOC_REQUIRE_PLATFORM_TESTS is
 * required a missing user, CLI, curl or ssh fails instead of skipping, and where
 * the `docker` tier is required so does a missing Docker or image.
 */
const VAULT_USER = process.env["HARPOC_TWO_UID_VAULT_USER"];
const AGENT_USER = process.env["HARPOC_TWO_UID_AGENT_USER"];
const RUNTIME_DIR = process.env["HARPOC_TWO_UID_RUNTIME_DIR"] ?? DEFAULT_RUNTIME_DIR;
const PASSWORD = "b6-model-b-master-pw-1";
const API_KEY_VALUE = "b6-model-b-api-key-value-8c2e";

/** The contract's ids as a literal — derived from the table, a deleted row would shrink both. */
const MODEL_B_SCENARIO_IDS = [
  "b-headless-fake-credential",
  "b-two-uid-value-route",
  "b-two-uid-session-file",
  "b-proxy-exposure",
  "b-proxy-echo-redaction",
  "b-agent-socket-exposure",
  "b-two-uid-environ",
  "b-docker-inspect",
  "b-negative-same-uid-environ",
];

describe.skipIf(process.platform !== "linux")(
  "deployment model B — the two-identity evidence (Linux only: sudo -n -u, /proc and POSIX ownership)",
  () => {
    let available = false;
    let dockerAvailable = false;
    let deployment: TwoIdentityDeployment | undefined;
    const emitted: EvidenceRecord[] = [];
    const dockerSkipped: string[] = [];

    beforeAll(async () => {
      let probeError: unknown;
      try {
        if (VAULT_USER === undefined || AGENT_USER === undefined) {
          throw new Error("HARPOC_TWO_UID_VAULT_USER and HARPOC_TWO_UID_AGENT_USER are not set");
        }
        for (const user of [VAULT_USER, AGENT_USER]) {
          const probe = await runAs(user, [process.execPath, resolveCliEntry(), "--version"]);
          if (probe.code !== 0) {
            throw new Error(`sudo -n -u ${user} cannot run the built CLI: ${probe.stderr.trim()}`);
          }
        }
        for (const tool of [
          ["curl", "--version"],
          ["ssh", "-V"],
        ]) {
          const probe = await runAs(AGENT_USER, tool);
          if (probe.code !== 0) {
            throw new Error(`the agent user cannot run ${tool.join(" ")}: ${probe.stderr.trim()}`);
          }
        }
        available = true;
      } catch (err) {
        probeError = err;
      }
      assertTierAvailable("two-uid", available, probeError);
      if (!available) return;

      let dockerError: unknown;
      try {
        const image = await runAs(AGENT_USER as string, [
          "docker",
          "image",
          "inspect",
          "--format",
          "{{.Id}}",
          MODEL_B_DOCKER_IMAGE,
        ]);
        if (image.code !== 0) {
          throw new Error(
            `the agent user cannot inspect ${MODEL_B_DOCKER_IMAGE}: ${image.stderr.trim()}`,
          );
        }
        dockerAvailable = true;
      } catch (err) {
        dockerError = err;
      }
      assertTierAvailable("docker", dockerAvailable, dockerError);

      deployment = await startTwoIdentityDeployment({
        vaultUser: VAULT_USER as string,
        agentUser: AGENT_USER as string,
        runtimeDir: RUNTIME_DIR,
        password: PASSWORD,
        apiKeyValue: API_KEY_VALUE,
      });
    }, 300_000);

    afterAll(async () => {
      await deployment?.stop();
    }, 120_000);

    for (const row of MODEL_B_SCENARIOS) {
      it(`${row.scenario}: matches its pre-registered outcome`, async (ctx) => {
        if (!available) return ctx.skip("the two-uid tier is unavailable and not required here");
        if (row.needs === "docker" && !dockerAvailable) {
          dockerSkipped.push(row.scenario);
          return ctx.skip(
            "Docker or its image is unavailable and the docker tier not required here",
          );
        }
        const d = deployment as TwoIdentityDeployment;
        const capture = captureCalls(...d.credentials.all, NEGATIVE_CONTROL_VALUE);
        const observed = await row.observe(d, capture);
        const calls = capture.calls();
        // A token is no credential the record redacts: a record that carries one is never written.
        const token = await d.agentToken();
        expect(JSON.stringify(calls).includes(token)).toBe(false);
        const record = recordModelB(
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
        // A divergence is a finding to report, not an expectation to edit.
        expect(
          record.match,
          `${row.scenario}: expected ${record.expected}, observed ${record.observed}`,
        ).toBe(true);
      }, 180_000);
    }

    it("runs every pre-registered model-B scenario — the docker row skipped only where its tier is not required", (ctx) => {
      if (!available) return ctx.skip("the two-uid tier is unavailable and not required here");
      const registered = loadExpectations(PREREGISTRATION_FILE_B);
      expect(registered.map((e) => e.scenario).sort()).toEqual([...MODEL_B_SCENARIO_IDS].sort());
      const ran = new Set(emitted.map((r) => r.scenario));
      expect(
        registered
          .filter((e) => !ran.has(e.scenario) && !dockerSkipped.includes(e.scenario))
          .map((e) => e.scenario),
      ).toEqual([]);
      expect(
        dockerSkipped.every(
          (s) => MODEL_B_SCENARIOS.find((row) => row.scenario === s)?.needs === "docker",
        ),
      ).toBe(true);
      expect(emitted).toHaveLength(MODEL_B_SCENARIOS.length - dockerSkipped.length);
      expect(emitted.every((r) => r.match)).toBe(true);
    });
  },
);
