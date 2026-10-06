import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it, vi } from "vitest";
import type { Arm, CallOutcome } from "../arms/arm.js";
import { encodingsOf } from "../assert/encodings.js";
import { OUTPUT_CHANNEL_ARMS } from "./output-channel.js";
import { RESPONSE_CHANNEL_ARMS } from "./response-channel.js";
import { Outcome } from "./scenario.js";
import type { ScenarioArm, ScenarioSetup } from "./scenario.js";

/**
 * The Harpoc verdicts of §6.2.6 and §6.2.7, driven without the fleet: each arm's
 * real `observe` against an arm that answers with a fixed outcome, shaped the
 * way `surfaces/mcp-http.ts` shapes it. A green fleet run never takes the
 * not-discriminating branch, so this is where it is falsifiable.
 */
vi.mock("../harness/vault.js", () => ({ storeSecret: vi.fn() }));
vi.mock("../harness/fixtures.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../harness/fixtures.js")>()),
  resolveGit: vi.fn(() => "/usr/bin/git"),
}));
vi.mock("../harness/attacker.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../harness/attacker.js")>()),
  resetSink: vi.fn(async () => undefined),
  sinkRequests: vi.fn(async () => []),
}));

const CREDENTIAL = "p4-verdict-marker:not/a-credential";
const SETUP: ScenarioSetup = {
  handle: "secret://p4-verdict",
  credential: CREDENTIAL,
  marker: join(tmpdir(), "e2e-i44-marker-never-created"),
};

function armOf(arms: ScenarioArm[], variant: string): ScenarioArm {
  return arms.find((a) => a.variant === variant) as ScenarioArm;
}

function harpocAnswering(outcome: CallOutcome): Arm {
  return {
    name: "harpoc",
    invoke: () => Promise.resolve(outcome),
    probeMetadata: () => Promise.reject(new Error("not probed")),
    close: () => Promise.resolve(),
  };
}

function completed(body: unknown): CallOutcome {
  const text = JSON.stringify(body);
  return { ok: true, result: { content: [{ type: "text", text }] }, text };
}

function refused(text: string): CallOutcome {
  return {
    ok: false,
    result: { isError: true, content: [{ type: "text", text }] },
    text,
    errorText: text,
  };
}

const SCOPE_REFUSAL = refused("Access denied: Token does not grant access to this secret");

describe("output-channel Harpoc verdicts", () => {
  const echo = armOf(OUTPUT_CHANNEL_ARMS, "encoding-base64");
  const gitContext = armOf(OUTPUT_CHANNEL_ARMS, "dedicated-context-git");

  it("records BLOCKED for an echo the sanitizer redacted", async () => {
    const outcome = completed({ type: "process", exit_code: 0, stdout: "[REDACTED]", stderr: "" });
    await expect(echo.observe(harpocAnswering(outcome), SETUP)).resolves.toBe(Outcome.BLOCKED);
  });

  it.each([
    ["a refused call", SCOPE_REFUSAL],
    ["a completed call with no [REDACTED]", completed({ type: "process", stdout: "", stderr: "" })],
  ])("throws instead of recording BLOCKED for %s", async (_, outcome) => {
    await expect(echo.observe(harpocAnswering(outcome), SETUP)).rejects.toThrow(
      /not discriminating/,
    );
  });

  it("records BLOCKED for a dedicated-context refusal by name", async () => {
    const outcome = refused(
      "'git' has a dedicated injection context and cannot be run through the process context",
    );
    await expect(gitContext.observe(harpocAnswering(outcome), SETUP)).resolves.toBe(
      Outcome.BLOCKED,
    );
  });

  it("throws for a dedicated-context arm refused for another reason", async () => {
    await expect(gitContext.observe(harpocAnswering(SCOPE_REFUSAL), SETUP)).rejects.toThrow(
      /not discriminating/,
    );
  });

  it("keeps the credential out of the not-discriminating diagnostic", async () => {
    const outcome = refused(`spawn failed: ${CREDENTIAL}`);
    const message = await gitContext.observe(harpocAnswering(outcome), SETUP).then(
      () => "",
      (err: unknown) => (err as Error).message,
    );
    for (const enc of encodingsOf(CREDENTIAL)) {
      expect(message).not.toContain(enc.needle);
    }
    expect(message).toContain("spawn failed: [REDACTED]");
  });

  it("credits the ladder's BLOCKED to the command-allowlist refusal", async () => {
    const ladder = armOf(OUTPUT_CHANNEL_ARMS, "non-interpreter-ladder");
    const outcome = refused("Command not in secret allowlist: node");
    await expect(ladder.observe(harpocAnswering(outcome), SETUP)).resolves.toBe(Outcome.BLOCKED);
  });

  it("refuses to credit a ladder refused for another reason", async () => {
    const ladder = armOf(OUTPUT_CHANNEL_ARMS, "non-interpreter-ladder");
    await expect(ladder.observe(harpocAnswering(SCOPE_REFUSAL), SETUP)).rejects.toThrow(
      /not discriminating/,
    );
  });

  it("credits network isolation's BLOCKED only to a completed call", async () => {
    const isolation = armOf(OUTPUT_CHANNEL_ARMS, "network-isolation");
    const outcome = completed({ type: "process", exit_code: 7, stdout: "", stderr: "" });
    await expect(isolation.observe(harpocAnswering(outcome), SETUP)).resolves.toBe(Outcome.BLOCKED);
  });

  it("refuses to credit an isolated call that failed for another reason", async () => {
    const isolation = armOf(OUTPUT_CHANNEL_ARMS, "network-isolation");
    await expect(isolation.observe(harpocAnswering(SCOPE_REFUSAL), SETUP)).rejects.toThrow(
      /arm is not discriminating: the sink stayed empty, but the call did not complete/,
    );
  });
});

describe("response-channel Harpoc verdicts", () => {
  const encoded = armOf(RESPONSE_CHANNEL_ARMS, "encoded-body");
  const reason = armOf(RESPONSE_CHANNEL_ARMS, "status-reason-phrase");

  it("records BLOCKED for an echo the sanitizer redacted", async () => {
    const outcome = completed({ type: "http", status: 200, body: '{"credential":"[REDACTED]"}' });
    await expect(encoded.observe(harpocAnswering(outcome), SETUP)).resolves.toBe(Outcome.BLOCKED);
  });

  it("records CHANNEL_ABSENT for a completed call with no status-text field", async () => {
    const outcome = completed({ type: "http", status: 200, headers: {}, body: "" });
    await expect(reason.observe(harpocAnswering(outcome), SETUP)).resolves.toBe(
      Outcome.CHANNEL_ABSENT,
    );
  });

  it.each([
    ["encoded-body", "a refused call", SCOPE_REFUSAL],
    ["encoded-body", "a completed call with no [REDACTED]", completed({ type: "http", body: "" })],
    ["status-reason-phrase", "a refused call", SCOPE_REFUSAL],
    ["partial-first8", "a refused call", SCOPE_REFUSAL],
  ])("%s throws instead of recording a defence for %s", async (variant, _, outcome) => {
    const arm = armOf(RESPONSE_CHANNEL_ARMS, variant);
    await expect(arm.observe(harpocAnswering(outcome), SETUP)).rejects.toThrow(
      /not discriminating/,
    );
  });
});
