import { emit } from "../evidence/record.js";
import type { EvidenceRecord } from "../evidence/record.js";
import { loadExpectations, expectationFor } from "../evidence/preregistration.js";
import type { Expectation, ExpectationKey } from "../evidence/preregistration.js";
import { EVIDENCE_FILE, PREREGISTRATION_FILE } from "./vault.js";

let cached: Expectation[] | null = null;

/**
 * One-call arm evidence: look up the pre-registered outcome (one file parse per
 * process), emit the record, and return it for the arm's `match` assertion. The
 * scenario descriptor is written ONCE — the previous per-arm boilerplate typed
 * it twice (lookup + emit), where a typo in only the emit copy records evidence
 * under a scenario that was never pre-registered while the arm still passes its
 * own lookup. An unregistered key still throws (`expectationFor`), before
 * anything is written.
 *
 * `interface` is carried beside the pre-registration key rather than inside it:
 * it is a property of the surface, not a dimension the outcome was registered
 * against, and pre-registration keys must stay byte-stable across tranches.
 */
export function recordArm(
  key: ExpectationKey & { interface: string },
  observed: string,
): EvidenceRecord {
  cached ??= loadExpectations(PREREGISTRATION_FILE);
  const expected = expectationFor(cached, key);
  return emit(EVIDENCE_FILE, { ...key, expected, observed });
}
