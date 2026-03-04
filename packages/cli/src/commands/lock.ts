import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../utils/vault-loader.js";
import { handleError, printSuccess } from "../utils/output.js";

export function registerLockCommand(program: Command): void {
  program
    .command("lock")
    .description("Lock the vault and erase session")
    .action(async (_options, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          await engine.lock();
          printSuccess("Vault locked.");
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
