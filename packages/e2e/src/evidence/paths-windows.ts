import { fileURLToPath } from "node:url";

/**
 * Deployment model B on Windows has its own pair, as B's has its own beside A's
 * (RD-B6-2): `model-b.test.ts` and `model-b.e2e.test.ts` pin B's file to exactly
 * the nine Linux ids, so the Windows rows cannot join it, and `recordModelB`
 * looks up B's file by a fixed path. `fileURLToPath`, never `URL.pathname`
 * (`paths.ts`).
 */
export const EVIDENCE_FILE_B_WINDOWS = fileURLToPath(
  new URL("../../evidence/run-b-windows.jsonl", import.meta.url),
);
export const PREREGISTRATION_FILE_B_WINDOWS = fileURLToPath(
  new URL("../../preregistration-model-b-windows.json", import.meta.url),
);
