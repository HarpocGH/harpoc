import { fileURLToPath } from "node:url";

/**
 * Where every scenario appends its record, and the committed expectations it is
 * checked against. `fileURLToPath`, never `URL.pathname`: the latter yields
 * "/C:/..." on Windows, which the fs layer resolves to "C:\C:\...".
 *
 * Single source for these paths — the evidence reset (vitest globalSetup) must
 * point at exactly the file the emitters write, without importing the vault
 * harness and everything underneath it.
 */
export const EVIDENCE_FILE = fileURLToPath(new URL("../../evidence/run.jsonl", import.meta.url));
export const PREREGISTRATION_FILE = fileURLToPath(
  new URL("../../preregistration.json", import.meta.url),
);

/**
 * Deployment model B's own pair (RD-B6-2): `scripts/tables.mjs`'s `checkGates`
 * refuses a pre-registered key no record of the run exercised, so B's rows
 * cannot share A's expectations or A's run without breaking A's tables.
 */
export const EVIDENCE_FILE_B = fileURLToPath(
  new URL("../../evidence/run-b.jsonl", import.meta.url),
);
export const PREREGISTRATION_FILE_B = fileURLToPath(
  new URL("../../preregistration-model-b.json", import.meta.url),
);
