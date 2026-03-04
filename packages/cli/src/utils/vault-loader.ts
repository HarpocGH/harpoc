import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { VAULT_DB_NAME, VAULT_DIR_NAME, SESSION_FILE_NAME } from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";

/**
 * Resolve the vault directory. Checks --vault-dir option, then cwd, then home.
 */
export function resolveVaultDir(vaultDirOption?: string): string {
  if (vaultDirOption) return vaultDirOption;

  const cwdVault = join(process.cwd(), VAULT_DIR_NAME);
  if (existsSync(cwdVault)) return cwdVault;

  return join(homedir(), VAULT_DIR_NAME);
}

/**
 * Create a VaultEngine instance pointed at the resolved vault directory.
 */
export function createEngine(vaultDir: string): VaultEngine {
  const dbPath = join(vaultDir, VAULT_DB_NAME);
  const sessionPath = join(vaultDir, SESSION_FILE_NAME);
  return new VaultEngine({ dbPath, sessionPath });
}

/**
 * Resolve a secret handle to its internal UUID.
 */
export async function resolveSecretId(engine: VaultEngine, handle: string): Promise<string> {
  return engine.resolveSecretId(handle);
}

/**
 * Load a VaultEngine with an active session (for commands that need an unlocked vault).
 * Throws VaultError.vaultLocked() if no valid session.
 */
export async function loadUnlockedEngine(vaultDir: string): Promise<VaultEngine> {
  const engine = createEngine(vaultDir);
  const loaded = await engine.loadSession();
  if (!loaded) {
    await engine.destroy();
    const { VaultError } = await import("@harpoc/shared");
    throw VaultError.vaultLocked();
  }
  return engine;
}
