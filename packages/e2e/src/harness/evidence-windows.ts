import { rmSync } from "node:fs";
import { emit } from "../evidence/record.js";
import type { EvidenceRecord } from "../evidence/record.js";
import type { CallEvidence } from "../evidence/calls.js";
import { loadExpectations, expectationFor } from "../evidence/preregistration.js";
import type { Expectation, ExpectationKey } from "../evidence/preregistration.js";
import {
  EVIDENCE_FILE_B_WINDOWS,
  PREREGISTRATION_FILE_B_WINDOWS,
} from "../evidence/paths-windows.js";

let cached: Expectation[] | null = null;

/**
 * `recordModelB` for deployment model B on Windows: the outcome looked up in
 * the Windows pre-registration, the record appended to its own evidence file.
 * `calls` are required and non-empty, as for B's — a committed file is
 * re-checked whole with `recheck --require-calls` — and an unregistered key or
 * an empty capture throws before anything is written.
 */
export function recordModelBWindows(
  key: ExpectationKey & { interface: string },
  observed: string,
  calls: CallEvidence[],
): EvidenceRecord {
  if (calls.length === 0) {
    throw new Error(
      `model-B Windows record ${key.scenario}: a record carries the calls it was judged on`,
    );
  }
  cached ??= loadExpectations(PREREGISTRATION_FILE_B_WINDOWS);
  const expected = expectationFor(cached, key);
  return emit(EVIDENCE_FILE_B_WINDOWS, { ...key, expected, observed, calls });
}

/** One run, one evidence file: the suite's `beforeAll` removes the previous run's (the global reset covers A's and B's files only). */
export function resetWindowsEvidence(): void {
  rmSync(EVIDENCE_FILE_B_WINDOWS, { force: true });
}
