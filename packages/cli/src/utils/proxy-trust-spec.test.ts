import { describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { parseProxyTrustSpec, parseProxyTrustSpecs } from "./proxy-trust-spec.js";

const KEYS = "(agent, secrets)";
const REQUIRED = "(agent and secrets are required)";
const PATTERN = "(letters, digits, _, - and the * wildcard)";

describe("parseProxyTrustSpec", () => {
  it("parses agent and secrets, the patterns split on + in order", () => {
    expect(parseProxyTrustSpec("agent=agent1,secrets=api-key+db-*")).toEqual({
      agent: "agent1",
      secrets: ["api-key", "db-*"],
    });
  });

  it("takes the keys in any order and one pattern alone", () => {
    expect(parseProxyTrustSpec("secrets=api-key,agent=agent1")).toEqual({
      agent: "agent1",
      secrets: ["api-key"],
    });
  });

  it("leaves an agent name in another case to the consumer directories' listing", () => {
    expect(parseProxyTrustSpec("agent=Agent1,secrets=api-key").agent).toBe("Agent1");
  });

  it.each([
    { label: "an empty spec", spec: "", message: '"" is not key=value' },
    {
      label: "a part without =",
      spec: "agent=agent1,secrets",
      message: '"secrets" is not key=value',
    },
    {
      label: "a comma list of patterns (the spec's own separator)",
      spec: "agent=agent1,secrets=api-key,db-*",
      message: '"db-*" is not key=value',
    },
    {
      label: "scope=use: the socket serves use alone, no permission is a key",
      spec: "agent=agent1,secrets=api-key,scope=use",
      message: `unknown key "scope" ${KEYS}`,
    },
    {
      label: "--issue-token's file key",
      spec: "agent=agent1,file=/run/harpoc/agent1/token.jwt,secrets=api-key",
      message: `unknown key "file" ${KEYS}`,
    },
    {
      label: "a key in another case",
      spec: "Agent=agent1,secrets=api-key",
      message: `unknown key "Agent" ${KEYS}`,
    },
    {
      label: "a space after the comma (nothing is trimmed)",
      spec: "agent=agent1, secrets=api-key",
      message: `unknown key " secrets" ${KEYS}`,
    },
    {
      label: "agent given twice",
      spec: "agent=agent1,agent=agent2,secrets=api-key",
      message: "agent given twice",
    },
    {
      label: "secrets given twice",
      spec: "agent=agent1,secrets=api-key,secrets=db-*",
      message: "secrets given twice",
    },
    { label: "an empty agent", spec: "agent=,secrets=api-key", message: "agent is empty" },
    {
      label: "an empty secrets (an empty pattern list names every secret)",
      spec: "agent=agent1,secrets=",
      message: "secrets is empty",
    },
    { label: "a missing agent", spec: "secrets=api-key", message: `agent is missing ${REQUIRED}` },
    { label: "a missing secrets", spec: "agent=agent1", message: `secrets is missing ${REQUIRED}` },
    {
      label: "an agent that is not an agent name",
      spec: "agent=agent 1,secrets=api-key",
      message: 'agent "agent 1" is not an agent name (letters, digits, _ and -; at most 255)',
    },
    {
      label: "a pattern outside the grammar",
      spec: "agent=agent1,secrets=db.*",
      message: `secrets: "db.*" is not a secret name or pattern ${PATTERN}`,
    },
    {
      label: "a handle in place of a name",
      spec: "agent=agent1,secrets=secret://api-key",
      message: `secrets: "secret://api-key" is not a secret name or pattern ${PATTERN}`,
    },
    {
      label: "an empty last pattern",
      spec: "agent=agent1,secrets=a+",
      message: `secrets: "" is not a secret name or pattern ${PATTERN}`,
    },
    {
      label: "an empty first pattern",
      spec: "agent=agent1,secrets=+a",
      message: `secrets: "" is not a secret name or pattern ${PATTERN}`,
    },
    {
      label: "an empty pattern between two",
      spec: "agent=agent1,secrets=a++b",
      message: `secrets: "" is not a secret name or pattern ${PATTERN}`,
    },
  ])("refuses $label INVALID_INPUT, naming the field", async ({ spec, message }) => {
    const err = await expectVaultError(() => parseProxyTrustSpec(spec), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(`--proxy-trust-socket: ${message}`);
  });

  it("refuses an agent name over 255 characters", async () => {
    const agent = "a".repeat(256);
    const err = await expectVaultError(
      () => parseProxyTrustSpec(`agent=${agent},secrets=api-key`),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `--proxy-trust-socket: agent "${agent}" is not an agent name (letters, digits, _ and -; at most 255)`,
    );
  });
});

describe("parseProxyTrustSpecs", () => {
  it("parses every value, in order; no value, no spec", () => {
    expect(parseProxyTrustSpecs([])).toEqual([]);
    expect(
      parseProxyTrustSpecs(["agent=agent2,secrets=db-*", "agent=agent1,secrets=api-key+db-*"]),
    ).toEqual([
      { agent: "agent2", secrets: ["db-*"] },
      { agent: "agent1", secrets: ["api-key", "db-*"] },
    ]);
  });

  it("refuses two specs for one agent", async () => {
    const err = await expectVaultError(
      () => parseProxyTrustSpecs(["agent=agent1,secrets=api-key", "agent=agent1,secrets=db-*"]),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      '--proxy-trust-socket: agent "agent1" is named by two specs (one trusted socket per agent)',
    );
  });

  it("refuses a malformed spec among valid ones", async () => {
    const err = await expectVaultError(
      () => parseProxyTrustSpecs(["agent=agent1,secrets=api-key", "agent=agent2,secrets="]),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe("--proxy-trust-socket: secrets is empty");
  });
});
