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
