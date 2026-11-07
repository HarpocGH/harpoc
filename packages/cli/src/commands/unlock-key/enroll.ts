import { lstatSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Command } from "commander";
import { VaultError } from "@harpoc/shared";
import { wipeBuffer, writeUnlockKeyFile } from "@harpoc/core";
import { createEngine, resolveVaultDir } from "../../utils/vault-loader.js";
import { promptPassword } from "../../utils/prompt.js";
import { handleError, printSuccess } from "../../utils/output.js";

/**
 * `--out`'s checks, before the password prompt: the enrolment replaces the slot before the key is
 * written, so a path that cannot take the key must be refused while nothing has changed. A value
 * Commander took from the next flag, an empty path, a missing directory and an existing entry (the
 * key goes to a new file only) are refused INVALID_INPUT; the writer's exclusive create stays the
 * guard against a file appearing in between.
 */
export function assertUnlockKeyOut(out: string): void {
  if (out.trim() === "") throw VaultError.invalidInput("--out: empty path");
  if (out.startsWith("-")) {
    throw VaultError.invalidInput(
      "--out: a flag, not a path (give a path that starts with a dash as ./-name)",
    );
  }
  const parent = dirname(resolve(out));
  let isDirectory = false;
  try {
    isDirectory = statSync(parent).isDirectory();
  } catch {
    // Refused below with the path, never the errno's text.
  }
  if (!isDirectory) throw VaultError.invalidInput(`--out: no such directory: ${parent}`);
  let exists: boolean;
  try {
    exists = lstatSync(out, { throwIfNoEntry: false }) !== undefined;
  } catch {
    throw VaultError.invalidInput(`--out: cannot check ${out} (is its directory searchable?)`);
  }
  if (exists) {
    throw VaultError.invalidInput(
      `--out: ${out} exists; the unlock key is written to a new file only`,
    );
  }
}

export function registerUnlockKeyEnrollCommand(unlockKey: Command): void {
  unlockKey
    .command("enroll")
    .description(
      "Enrol the machine-bound unlock key — a second KEK slot under a new random 32-byte key — after a master-password prompt; the key is written to --out for a sealer and never printed, and an enrolled key is replaced",
    )
    .requiredOption(
      "--out <path>",
      "New file the unlock key is written to (owner-only; refused if it exists) — seal it, e.g. with deploy/linux/enroll-unlock-key.sh",
    )
    .action(async (options: { out: string }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        assertUnlockKeyOut(options.out);
        const password = await promptPassword();
        const engine = createEngine(vaultDir);
        try {
          await engine.unlock(password);
          const { enrolled } = await engine.unlockKeyStatus();
          const key = await engine.enrollUnlockKey();
          try {
            await writeUnlockKeyFile(options.out, key);
          } finally {
            wipeBuffer(key);
          }
          const seal = `(systemd: deploy/linux/enroll-unlock-key.sh ${options.out})`;
          printSuccess(
            enrolled
              ? `Unlock key replaced: written to ${options.out} (owner-only); the previous key no longer unlocks the vault. Seal the new one and restart the daemon ${seal}.`
              : `Unlock key enrolled: written to ${options.out} (owner-only). Seal it before use ${seal}.`,
          );
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
