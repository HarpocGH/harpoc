import { describe, expect, it } from "vitest";
import { HELD_OUTCOMES, LEAKED_OUTCOMES } from "../../scripts/recheck.mjs";
import { PREREGISTRATION_FILE_B } from "../evidence/paths.js";
import {
  expectationFor,
  loadExpectations,
  validateExpectationSet,
} from "../evidence/preregistration.js";
import { consumerPaths } from "../harness/two-identity.js";
import {
  CONTAINER_CLIENT,
  MODEL_B_DOCKER_IMAGE,
  MODEL_B_SCENARIOS,
  dockerRunArgs,
} from "./model-b.js";

/**
 * The contract's scenario ids (program plan § Cross-tranche interfaces, the
 * Evidence row, and RD-B6-1's eighth and ninth), as a literal: a list derived from the
 * table would shrink with it (the `PHASE4_SCENARIOS` lesson).
 */
const CONTRACT_IDS = [
  "b-two-uid-environ",
  "b-two-uid-value-route",
  "b-two-uid-session-file",
  "b-proxy-exposure",
  "b-proxy-echo-redaction",
  "b-agent-socket-exposure",
  "b-headless-fake-credential",
  "b-negative-same-uid-environ",
  "b-docker-inspect",
];

describe("the model-B scenario table and its pre-registration", () => {
  const expectations = loadExpectations(PREREGISTRATION_FILE_B);

  it("holds the set invariants: no duplicate key, no OS-keyed orphan, no half comparison", () => {
    expect(validateExpectationSet(expectations)).toEqual([]);
  });

  it("registers exactly the contract's nine scenario ids", () => {
    expect(expectations.map((e) => e.scenario).sort()).toEqual([...CONTRACT_IDS].sort());
  });

  it("gives every scenario of the table exactly one expectation, the outcome the table states", () => {
    for (const row of MODEL_B_SCENARIOS) {
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
    const ids = new Set(MODEL_B_SCENARIOS.map((r) => r.scenario));
    expect(ids.size).toBe(MODEL_B_SCENARIOS.length);
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
    // RD-B6-1: recheck does not judge BYPASSED; --require-calls still needs its calls.
    const judged: readonly string[] = [...HELD_OUTCOMES, ...LEAKED_OUTCOMES, "BYPASSED"];
    for (const e of expectations) expect(judged, e.scenario).toContain(e.expected);
  });

  it("runs the negative control in process and every other row on the deployment; only the docker row needs Docker", () => {
    expect(MODEL_B_SCENARIOS.filter((r) => r.surface === "engine").map((r) => r.scenario)).toEqual([
      "b-negative-same-uid-environ",
    ]);
    expect(MODEL_B_SCENARIOS.filter((r) => r.needs === "docker").map((r) => r.scenario)).toEqual([
      "b-docker-inspect",
    ]);
  });

  it("keys each record's interface to the audit interface its rows are verified against", () => {
    expect(Object.fromEntries(MODEL_B_SCENARIOS.map((r) => [r.scenario, r.interface]))).toEqual({
      "b-headless-fake-credential": "rest",
      "b-two-uid-value-route": "rest",
      "b-two-uid-session-file": "filesystem",
      "b-proxy-exposure": "proxy",
      "b-proxy-echo-redaction": "proxy",
      "b-agent-socket-exposure": "ssh_agent",
      "b-two-uid-environ": "proxy+ssh_agent",
      "b-docker-inspect": "proxy",
      "b-negative-same-uid-environ": "engine",
    });
  });
});

/**
 * RD-B6-10 (R3, E-5): the docker row's container sees the consumer directory
 * read-only at its own path and the token file's path, never the token.
 */
describe("the docker row's container", () => {
  it("mounts the consumer directory read-only at its own path and passes the token's path, never the token", () => {
    const token = "fixture-token-b6-docker";
    const argv = dockerRunArgs(
      {
        consumer: consumerPaths("/run/harpoc", "agent"),
        placeholders: { apiKey: "harpoc:api-key" },
        agentEnv: { HARPOC_PROXY_BASE: "http://127.0.0.1:3128/", HARPOC_PROXY_TOKEN: token },
        echo: { port: 41003 },
      },
      "1002",
      "1003",
      "harpoc-b6-0000",
    );
    const runs = [
      ["docker", "run"],
      ["--pull", "never"],
      ["--network", "host"],
      ["--user", "1002:1003"],
      ["--mount", "type=bind,source=/run/harpoc/agent,target=/run/harpoc/agent,readonly"],
      ["-e", "HARPOC_PLACEHOLDER_API_KEY=harpoc:api-key"],
      ["-e", "HARPOC_PROXY_BASE=http://127.0.0.1:3128/"],
      ["-e", "HARPOC_PROXY_TOKEN_FILE=/run/harpoc/agent/token.jwt"],
      [MODEL_B_DOCKER_IMAGE, "node", "-e", CONTAINER_CLIENT, "127.0.0.1:41003/echo/held"],
    ];
    let from = 0;
    for (const run of runs) {
      const at = argv.findIndex(
        (_, i) => i >= from && run.every((part, j) => argv[i + j] === part),
      );
      expect(at, run.slice(0, 2).join(" ")).toBeGreaterThanOrEqual(0);
      from = at + run.length;
    }
    expect(CONTAINER_CLIENT.includes("process.env.HARPOC_PROXY_TOKEN_FILE")).toBe(true);
    // Boolean-shaped: a failing comparison never echoes the token.
    expect(argv.some((part) => part.includes(token))).toBe(false);
  });
});
