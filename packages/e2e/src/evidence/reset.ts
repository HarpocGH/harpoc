import { rmSync } from "node:fs";
import { EVIDENCE_FILE } from "./paths.js";

/**
 * Vitest globalSetup: one run, one evidence file. `emit` appends, so without
 * this reset records from earlier runs — and earlier commits — would
 * accumulate in run.jsonl and every consumer would have to filter by `commit`.
 */
export default function resetEvidence(): void {
  rmSync(EVIDENCE_FILE, { force: true });
}
