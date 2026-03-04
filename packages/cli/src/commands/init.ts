import { mkdirSync, existsSync } from "node:fs";
import type { Command } from "commander";
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
        if (!existsSync(vaultDir)) {
          mkdirSync(vaultDir, { recursive: true });
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
