import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VaultEngine } from "@harpoc/core";
import { ErrorCode, VAULT_DB_NAME, SESSION_FILE_NAME, VaultError } from "@harpoc/shared";

export interface TestVault {
  engine: VaultEngine;
  dbPath: string;
  sessionPath: string;
  tmpDir: string;
}

/**
 * Create a VaultEngine with a fresh temp directory.
 * If `sharedDir` is provided, reuses that directory (for multi-engine tests).
 */
export function createTestVault(sharedDir?: string): TestVault {
  const tmpDir = sharedDir ?? mkdtempSync(join(tmpdir(), "harpoc-integ-"));
  const dbPath = join(tmpDir, VAULT_DB_NAME);
  const sessionPath = join(tmpDir, SESSION_FILE_NAME);
  const engine = new VaultEngine({ dbPath, sessionPath });
  return { engine, dbPath, sessionPath, tmpDir };
}

/**
 * Destroy an engine and clean up the temp directory.
 */
export async function destroyTestVault(vault: TestVault): Promise<void> {
  await vault.engine.destroy();
  rmSync(vault.tmpDir, { recursive: true, force: true });
}

/**
 * Register the agent identities a suite mints tokens or grants for — the v1.4
 * registration gate refuses an unregistered agent-typed principal. Idempotent,
 * so a suite may call it once per test without tracking what it already did.
 */
export function registerAgents(engine: VaultEngine, ...names: string[]): void {
  for (const name of names) {
    try {
      engine.registerAgent({ name });
    } catch (err) {
      if (!(err instanceof VaultError) || err.code !== ErrorCode.AGENT_EXISTS) throw err;
    }
  }
}
