import { ATTACKER } from "./backends.js";
import { sightings } from "../assert/opacity.js";
import type { CallOutcome } from "../arms/arm.js";

export interface SinkRequest {
  method: string;
  path: string;
  authorization: string | null;
  headers: Record<string, string>;
  query: Record<string, string>;
  body: string;
}

/**
 * Empty the sink and confirm it is empty.
 *
 * Both halves matter. The recorder survives between runs — it lives in a
 * long-running container — so an entry left by an earlier run could satisfy an
 * arm whose call never happened. Asserting emptiness immediately before the
 * call is what makes "the sink stayed empty" a falsifiable per-arm property
 * rather than a statement about the container's whole lifetime. (Phase 3's
 * review found exactly this defect in the mcp arm's corroboration.)
 */
export async function resetSink(): Promise<void> {
  const deleted = await fetch(ATTACKER.recordedUrl, { method: "DELETE" });
  if (deleted.status !== 204) {
    throw new Error(`attacker sink reset failed with status ${String(deleted.status)}`);
  }
  const remaining = await sinkRequests();
  if (remaining.length > 0) {
    throw new Error(`attacker sink still holds ${String(remaining.length)} request(s) after reset`);
  }
}

export async function sinkRequests(): Promise<SinkRequest[]> {
  const response = await fetch(ATTACKER.recordedUrl);
  if (response.status !== 200) {
    throw new Error(`attacker sink query failed with status ${String(response.status)}`);
  }
  return ((await response.json()) as { requests: SinkRequest[] }).requests;
}

/** Whether the credential reached the sink, in any encoding, anywhere. */
export function sinkSawCredential(credential: string, arrived: SinkRequest[]): boolean {
  return sightings(credential, { result: arrived }).length > 0;
}

/**
 * The verdict for a target-manipulation arm, as one rule applied to both arms —
 * that is what keeps the paired row a comparison of credential-handling layers
 * rather than of two differently-written checks.
 *
 * The final branch is the anti-vacuity guard: a call that SUCCEEDED while
 * nothing reached the sink means the arm did not exercise what it claims (a
 * misdirected URL, a backend that never ran), and recording BLOCKED there would
 * manufacture a passing cell out of a broken one.
 */
export function classifyExfiltration(
  outcome: CallOutcome,
  credential: string,
  arrived: SinkRequest[],
): "EXFILTRATED" | "BLOCKED" {
  if (sinkSawCredential(credential, arrived)) return "EXFILTRATED";
  if (!outcome.ok) return "BLOCKED";
  throw new Error(
    "arm is not discriminating: the call succeeded but the credential never reached the sink — " +
      "the attack path is broken, so neither BLOCKED nor EXFILTRATED would mean anything",
  );
}
