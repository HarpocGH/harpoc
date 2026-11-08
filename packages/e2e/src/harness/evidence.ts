import { emit } from "../evidence/record.js";
import type { EvidenceRecord } from "../evidence/record.js";
import type { CallEvidence } from "../evidence/calls.js";
import { loadExpectations, expectationFor } from "../evidence/preregistration.js";
import type { Expectation, ExpectationKey } from "../evidence/preregistration.js";
import { EVIDENCE_FILE_B, PREREGISTRATION_FILE_B } from "../evidence/paths.js";
import { EVIDENCE_FILE, PREREGISTRATION_FILE } from "./vault.js";

let cached: Expectation[] | null = null;
let cachedB: Expectation[] | null = null;

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
 *
 * `calls` are the surface calls the verdict was judged on (`callEvidence` /
 * `recordingArm` in evidence/calls.ts), written into the record so it can be
 * re-checked from its own content (I1, test-review-2026-10-09).
 */
export function recordArm(
  key: ExpectationKey & { interface: string },
  observed: string,
  calls?: CallEvidence[],
): EvidenceRecord {
  cached ??= loadExpectations(PREREGISTRATION_FILE);
  const expected = expectationFor(cached, key);
  return emit(EVIDENCE_FILE, {
    ...key,
    expected,
    observed,
    ...(calls === undefined ? {} : { calls }),
  });
}

/**
 * `recordArm` for deployment model B (RD-B6-2): the outcome looked up in B's
 * own pre-registration, the record appended to B's own evidence file. `calls`
 * are required and non-empty — a committed B file is re-checked whole with
 * `recheck --require-calls`, which refuses a record without them — and an
 * unregistered key or an empty capture throws before anything is written.
 */
export function recordModelB(
  key: ExpectationKey & { interface: string },
  observed: string,
  calls: CallEvidence[],
): EvidenceRecord {
  if (calls.length === 0) {
    throw new Error(`model-B record ${key.scenario}: a record carries the calls it was judged on`);
  }
  cachedB ??= loadExpectations(PREREGISTRATION_FILE_B);
  const expected = expectationFor(cachedB, key);
  return emit(EVIDENCE_FILE_B, { ...key, expected, observed, calls });
}
