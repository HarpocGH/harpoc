import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Command } from "commander";
import { VAULT_DB_NAME, VAULT_DIR_NAME, SESSION_FILE_NAME, VaultError } from "@harpoc/shared";
import type { AuditEventType, CallerContext } from "@harpoc/shared";
import { VaultEngine, wipeBuffer } from "@harpoc/core";
import type { VaultEngineOptions } from "@harpoc/core";
import { handleError } from "./output.js";

/** The engine options a command chooses: the session mode alone (`server start --session`). */
export type EngineOptions = Pick<VaultEngineOptions, "sessionMode">;

/**
 * Resolve the vault directory. Checks --vault-dir option, then cwd, then home;
 * an empty or whitespace-only --vault-dir refuses INVALID_INPUT, and so does a
 * value starting with `-`: Commander takes the next flag as the path
 * (`--vault-dir --http`); a path that starts with a dash is given as `./-name`
 * (2026-10-22).
 */
export function resolveVaultDir(vaultDirOption?: string): string {
  if (vaultDirOption !== undefined) {
    if (vaultDirOption.trim() === "") throw VaultError.invalidInput("--vault-dir: empty path");
    if (vaultDirOption.startsWith("-")) {
      throw VaultError.invalidInput(
        "--vault-dir: a flag, not a path (give a path that starts with a dash as ./-name)",
      );
    }
    return vaultDirOption;
  }

  const cwdVault = join(process.cwd(), VAULT_DIR_NAME);
  if (existsSync(cwdVault)) return cwdVault;

  return join(homedir(), VAULT_DIR_NAME);
}

/**
 * The root program's preAction hook: an empty or flag-shaped --vault-dir refuses before any
 * command's action runs, through the --json envelope where the command has one.
 */
export function refuseEmptyVaultDir(program: Command, actionCommand: Command): void {
  try {
    resolveVaultDir(program.opts<{ vaultDir?: string }>().vaultDir);
  } catch (err) {
    handleError(err, actionCommand.optsWithGlobals<{ json?: boolean }>().json === true);
  }
}

/**
 * Create a VaultEngine instance pointed at the resolved vault directory. Without `options` the
 * engine is built exactly as before B5 — no `sessionMode` key, the engine's file default.
 */
export function createEngine(vaultDir: string, options?: EngineOptions): VaultEngine {
  const dbPath = join(vaultDir, VAULT_DB_NAME);
  const sessionPath = join(vaultDir, SESSION_FILE_NAME);
  return new VaultEngine({
    dbPath,
    sessionPath,
    ...(options?.sessionMode !== undefined ? { sessionMode: options.sessionMode } : {}),
    onSessionFilePermissionRepairFailure: (error) => {
      console.error(`Warning: ${error.message}`);
    },
    onJobWrapperUnavailable: (reason) => {
      console.error(
        `Warning: the Windows job wrapper is unavailable (${reason}); spawns run on the taskkill tier and strict_tree_exit secrets refuse`,
      );
    },
  });
}

/**
 * Resolve a secret handle to its internal UUID. A token-bearing command passes
 * the caller it resolved and, where its semantics are not a read, its own event
 * type, so a failed probe is attributed and lands where an operator filtering
 * that command's events will see it — the REST routes' shape (D2b, 2026-09-23).
 */
export async function resolveSecretId(
  engine: VaultEngine,
  handle: string,
  caller?: CallerContext,
  eventType?: AuditEventType,
): Promise<string> {
  return engine.resolveSecretId(handle, caller, eventType);
}

/**
 * Load a VaultEngine with an active session (for commands that need an unlocked vault).
 * Throws VaultError.vaultLocked() if no valid session. In memory mode the engine installs the
 * session's keys and holds no session of its own (`server start --session memory`).
 */
export async function loadUnlockedEngine(
  vaultDir: string,
  options?: EngineOptions,
): Promise<VaultEngine> {
  const engine = createEngine(vaultDir, options);
  const loaded = await engine.loadSession();
  if (!loaded) {
    await engine.destroy();
    const { VaultError } = await import("@harpoc/shared");
    throw VaultError.vaultLocked();
  }
  return engine;
}

/**
 * Unlock a VaultEngine with the machine-bound unlock key (`server start --unlock-key-file` /
 * `--unlock-credential`): the daemon unlocks its own engine instead of loading a session. The key
 * is handed over as it is — not copied, so the engine's own wipe reaches it — and wiped here as
 * well, whatever happens; a refused unlock destroys the engine and rethrows.
 */
export async function unlockEngineWithKey(
  vaultDir: string,
  key: Uint8Array,
  options?: EngineOptions,
): Promise<VaultEngine> {
  try {
    const engine = createEngine(vaultDir, options);
    try {
      await engine.unlockWithKey(key);
    } catch (err) {
      await engine.destroy();
      throw err;
    }
    return engine;
  } finally {
    wipeBuffer(key);
  }
}
