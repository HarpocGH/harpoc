import { lstatSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import type { Command } from "commander";
import { VaultError } from "@harpoc/shared";
import { assertOwnerOnlyDir, assertUnlinkedDir, isHeldPath } from "@harpoc/core";
import { loadUnlockedEngine, resolveVaultDir } from "../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../utils/output.js";

function directoryOf(path: string): string | undefined {
  try {
    const dir = realpathSync(path);
    return statSync(dir).isDirectory() ? dir : undefined;
  } catch {
    return undefined;
  }
}

async function assertBackupTarget(file: string): Promise<string> {
  if (file.trim() === "") throw VaultError.invalidInput("<file>: empty path");
  if (file.startsWith("-")) {
    throw VaultError.invalidInput(
      "<file>: a flag, not a path (give a path that starts with a dash as ./-name)",
    );
  }
  const target = resolve(file);
  let exists: boolean;
  try {
    exists = lstatSync(target, { throwIfNoEntry: false }) !== undefined;
  } catch {
    throw VaultError.invalidInput(`<file>: cannot check ${file} (is its directory searchable?)`);
  }
  if (exists) {
    throw VaultError.invalidInput(`<file>: ${file} exists; a backup is written to a new file only`);
  }
  const parent = dirname(target);
  const dir = directoryOf(parent);
  if (dir === undefined) throw VaultError.invalidInput(`<file>: no such directory: ${parent}`);
  const win32 = process.platform === "win32";
  if (win32) assertUnlinkedDir(parent, "<file>");
  const real = join(dir, basename(target));
  const held = await isHeldPath(real);
  if (win32) assertOwnerOnlyDir(dir, "<file>");
  if (!held) {
    throw VaultError.invalidInput(
      "<file>: a directory on its path can be changed by another account",
    );
  }
  return real;
}

const INTERRUPTIONS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"] as const;

export function registerBackupCommand(program: Command): void {
  program
    .command("backup <file>")
    .description("Write a copy of the vault to a new file (it opens by password alone)")
    .option("--json", "Output as JSON")
    .action(async (file: string, options: { json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const target = await assertBackupTarget(file);
        const engine = await loadUnlockedEngine(vaultDir);
        const interruption = new AbortController();
        const interrupt = (): void => interruption.abort();
        for (const signal of INTERRUPTIONS) process.on(signal, interrupt);
        try {
          const written = await engine.backupToFile(target, { signal: interruption.signal });
          if (options.json) {
            printJson({ backup_file: written.file });
          } else {
            printSuccess(`Backup written to ${written.file}`);
          }
        } finally {
          for (const signal of INTERRUPTIONS) process.removeListener(signal, interrupt);
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
