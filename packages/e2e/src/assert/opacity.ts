import { scan } from "./scan.js";
import type { Sighting } from "./scan.js";
import { serializeError } from "./serialize-error.js";

/** Every channel an agent can observe after a `use_secret` call. */
export interface Observation {
  result?: unknown;
  error?: unknown;
  auditRows?: unknown[];
  stdout?: string;
  stderr?: string;
  parentEnv?: NodeJS.ProcessEnv;
}

function channels(obs: Observation): Array<[string, unknown]> {
  const out: Array<[string, unknown]> = [];
  if ("result" in obs) out.push(["result", obs.result]);
  if ("auditRows" in obs) out.push(["audit", obs.auditRows]);
  if (obs.stdout !== undefined) out.push(["stdout", obs.stdout]);
  if (obs.stderr !== undefined) out.push(["stderr", obs.stderr]);
  if (obs.parentEnv !== undefined) out.push(["parentEnv", { ...obs.parentEnv }]);
  if ("error" in obs && obs.error !== undefined) out.push(["error", serializeError(obs.error)]);
  return out;
}

/**
 * Success criteria 1 and 2 as one callable check: the credential must not
 * appear in any encoding, at any structural position, in any observable
 * channel — result, thrown error, audit rows, child stdio, parent environment.
 */
export function assertOpaque(secret: string, obs: Observation): void {
  const hits: Sighting[] = [];
  for (const [name, node] of channels(obs)) {
    for (const hit of scan(secret, node)) {
      hits.push({ ...hit, path: `${name}${hit.path.slice(1)}` });
    }
  }
  if (hits.length === 0) return;

  const detail = hits.map((h) => `  ${h.path} (${h.position}, ${h.encoding})`).join("\n");
  throw new Error(
    `credential plaintext reached the caller in ${hits.length} position(s):\n${detail}`,
  );
}

/**
 * Negative control. Blanket redaction would satisfy every opacity assertion,
 * so each scenario also pins that a benign marker survived untouched.
 */
export function assertPresent(needle: string, obs: Observation): void {
  for (const [, node] of channels(obs)) {
    if (scan(needle, node).length > 0) return;
  }
  throw new Error(
    `expected the benign marker "${needle}" to survive, but it appears in no channel — ` +
      `redaction is blanket, not targeted`,
  );
}
