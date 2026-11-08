import { afterEach, describe, expect, it, vi } from "vitest";
import { HELD_OUTCOMES, LEAKED_OUTCOMES } from "../../scripts/recheck.mjs";
import { PREREGISTRATION_FILE_B } from "../evidence/paths.js";
import { PREREGISTRATION_FILE_B_WINDOWS } from "../evidence/paths-windows.js";
import {
  expectationFor,
  loadExpectations,
  validateExpectationSet,
} from "../evidence/preregistration.js";
import type { ChildRun } from "../harness/child.js";
import { SSH2_EXEC_REPLY } from "../harness/ssh2-server.js";
import type { SshAuthEvent } from "../harness/ssh2-server.js";
import type { AuditRow } from "../harness/two-identity.js";
import type { TwoAccountDeployment } from "../harness/two-identity-windows.js";
import { MODEL_B_WINDOWS_SCENARIOS, captureCalls } from "./model-b-windows.js";
import type { ModelBWindowsScenario } from "./model-b-windows.js";
import { Outcome } from "./scenario.js";

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

/**
 * The pipe row on a stubbed deployment: the agent's ssh is a canned run and the
 * audit trail a canned list, so the row's verdict and its diagnostic are read
 * without accounts (`systemPaths` needs a `SystemRoot`, stubbed off Windows).
 */
describe("the pipe row's verdict and its diagnostic (a stubbed deployment)", () => {
  const AGENT = "agent1";
  const API_KEY = "unit-fixture-api-key-7c2b";
  const PASSWORD_NEEDLE = "unit-fixture-agent-pw-9d1e";
  const pipeRow = MODEL_B_WINDOWS_SCENARIOS.find(
    (r) => r.scenario === "b-win-agent-pipe-exposure",
  ) as ModelBWindowsScenario;

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  function stubbed(run: ChildRun, after: AuditRow[], event?: SshAuthEvent): TwoAccountDeployment {
    const events: SshAuthEvent[] = [];
    let reads = 0;
    vi.stubEnv("SystemRoot", "C:\\Windows");
    return {
      agentUser: AGENT,
      consumer: { agentPipe: `\\\\.\\pipe\\harpoc-${AGENT}-ssh-agent` },
      agentFiles: { knownHosts: "C:/b7/known_hosts", identity: "C:/b7/id.pub" },
      sshServer: { events, port: 2222 },
      credentials: { all: [API_KEY] },
      auditRows: async () => (reads++ === 0 ? [] : after),
      asAgent: async () => {
        if (event !== undefined) events.push(event);
        return run;
      },
    } as unknown as TwoAccountDeployment;
  }

  it("lacking its proof, rethrows the same message with ssh's exit code and its stderr's last 20 lines, redacted as the row's capture redacts", async () => {
    const lines = Array.from({ length: 25 }, (_, i) => `debug1: line ${String(i + 1)}`);
    const stderr = [
      ...lines,
      `debug1: an echo of ${PASSWORD_NEEDLE}`,
      "Permission denied (publickey).",
    ].join("\r\n");
    const d = stubbed({ code: 255, stdout: "", stderr: `${stderr}\r\n` }, []);
    let thrown: unknown;
    try {
      await pipeRow.observe(d, captureCalls(API_KEY, PASSWORD_NEEDLE));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    const message = (thrown as Error).message;
    expect(
      message.startsWith(
        "arm is not discriminating: b-win-agent-pipe-exposure lacks its proof (completed, bound, signatureVerified, attributed)",
      ),
    ).toBe(true);
    expect(message.includes("ssh exited 255")).toBe(true);
    expect(message.includes(PASSWORD_NEEDLE)).toBe(false);
    expect(
      message.includes("debug1: an echo of [CREDENTIAL]\nPermission denied (publickey)."),
    ).toBe(true);
    expect(message.includes("debug1: line 8\n")).toBe(true);
    expect(message.includes("debug1: line 7\n")).toBe(false);
  });

  it("on its proof the row is OPAQUE, as before", async () => {
    const used: AuditRow = {
      id: 7,
      event_type: "secret.use",
      success: true,
      principal_id: AGENT,
      secret_id: "s1",
      detail: {
        context: "ssh_agent",
        interface: "ssh_agent",
        host: "127.0.0.1",
        key_type: "ssh-ed25519",
      },
    };
    const d = stubbed(
      { code: 0, stdout: `${SSH2_EXEC_REPLY}\n`, stderr: "debug1: bound agent to hostkey\r\n" },
      [used],
      { user: "harpoc-b7", method: "publickey", signed: true, verified: true },
    );
    expect(await pipeRow.observe(d, captureCalls(API_KEY))).toBe(Outcome.OPAQUE);
  });
});
