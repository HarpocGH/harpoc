import {
  parseSecretPatterns,
  parseSpecAgent,
  parseSpecParts,
  specRefusal,
} from "./spec-grammar.js";

/** One consumer opted in to its trusted proxy socket, with the secret-name patterns it serves. */
export interface ProxyTrustSpec {
  agent: string;
  secrets: string[];
}

const FLAG = "--proxy-trust-socket";
const KEYS = ["agent", "secrets"] as const;

/**
 * One `server start --proxy-trust-socket` value: `agent=<name>,secrets=<pattern>[+<pattern>…]`,
 * in `--issue-token`'s grammar (`spec-grammar.ts`). Both keys required, no pattern empty — an
 * empty pattern list would leave the socket's caller name-unrestricted. The permission is no
 * key: a trusted socket serves `use` alone. Every refusal is `INVALID_INPUT` naming the field.
 */
export function parseProxyTrustSpec(spec: string): ProxyTrustSpec {
  const values = parseSpecParts(FLAG, spec, KEYS, KEYS);
  const agent = parseSpecAgent(FLAG, values.get("agent") as string);
  const secrets = parseSecretPatterns(FLAG, values.get("secrets") as string);
  return { agent, secrets };
}

/** Every `--proxy-trust-socket` value, in order; two specs naming one agent are refused. */
export function parseProxyTrustSpecs(values: readonly string[]): ProxyTrustSpec[] {
  const specs = values.map(parseProxyTrustSpec);
  const agents = new Set<string>();
  for (const { agent } of specs) {
    if (agents.has(agent)) {
      throw specRefusal(
        FLAG,
        `agent ${JSON.stringify(agent)} is named by two specs (one trusted socket per agent)`,
      );
    }
    agents.add(agent);
  }
  return specs;
}
