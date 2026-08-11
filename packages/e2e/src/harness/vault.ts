import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { VaultEngine } from "@harpoc/core";
import { VAULT_DB_NAME, SESSION_FILE_NAME, SecretType } from "@harpoc/shared";

/**
 * Where every scenario appends its record, and the committed expectations it is
 * checked against. `fileURLToPath`, never `URL.pathname`: the latter yields
 * "/C:/..." on Windows, which the fs layer resolves to "C:\C:\...".
 */
export const EVIDENCE_FILE = fileURLToPath(new URL("../../evidence/run.jsonl", import.meta.url));
export const PREREGISTRATION_FILE = fileURLToPath(
  new URL("../../preregistration.json", import.meta.url),
);

export interface HarnessVault {
  engine: VaultEngine;
  tmpDir: string;
  destroy(): Promise<void>;
}

export async function createHarnessVault(password: string): Promise<HarnessVault> {
  const tmpDir = mkdtempSync(join(tmpdir(), "harpoc-e2e-"));
  const engine = new VaultEngine({
    dbPath: join(tmpDir, VAULT_DB_NAME),
    sessionPath: join(tmpDir, SESSION_FILE_NAME),
  });
  await engine.initVault(password);

  return {
    engine,
    tmpDir,
    async destroy() {
      await engine.destroy();
      rmSync(tmpDir, { recursive: true, force: true });
    },
  };
}

/** Store a credential and return its opaque handle. */
export async function storeSecret(
  vault: HarnessVault,
  name: string,
  value: string,
): Promise<string> {
  const created = await vault.engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new TextEncoder().encode(value),
  });
  return created.handle;
}
