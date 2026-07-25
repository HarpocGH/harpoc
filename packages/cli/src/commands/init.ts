import { chmodSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Command } from "commander";
import { VAULT_DB_NAME } from "@harpoc/shared";
import { resolveVaultDir, createEngine } from "../utils/vault-loader.js";
import { promptPassword } from "../utils/prompt.js";
import { handleError, printSuccess } from "../utils/output.js";

export function registerInitCommand(program: Command): void {
  program
    .command("init")
    .description("Create a new vault")
    .action(async (_options, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const dbPath = join(vaultDir, VAULT_DB_NAME);
        if (existsSync(dbPath)) {
          console.error(
            `Error: a vault already exists at ${dbPath}.\n` +
              `Use 'harpoc unlock' to open it. To start over, delete the vault directory manually.`,
          );
          process.exit(1);
        }

        // 0700, like the session file's 0600: the directory was created with no
        // explicit mode, so on POSIX it was umask-dependent — typically
        // world-readable and traversable (L11). Applied at creation (umask can
        // only tighten it) with a chmod repair for a pre-existing directory.
        if (!existsSync(vaultDir)) {
          mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
        }
        if (process.platform !== "win32") {
          try {
            chmodSync(vaultDir, 0o700);
          } catch (err) {
            console.error(
              `Warning: could not restrict ${vaultDir} to owner-only access (${err instanceof Error ? err.message : String(err)})`,
            );
          }
        }

        const password = await promptPassword("Choose a master password: ");
        if (!password) {
          console.error("Error: Password cannot be empty.");
          process.exit(1);
        }

        const confirm = await promptPassword("Confirm password: ");
        if (password !== confirm) {
          console.error("Error: Passwords do not match.");
          process.exit(1);
        }

        const engine = createEngine(vaultDir);
        try {
          const { vaultId } = await engine.initVault(password);
          printSuccess(`Vault created (${vaultId})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
