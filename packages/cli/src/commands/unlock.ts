import type { Command } from "commander";
import { resolveVaultDir, createEngine } from "../utils/vault-loader.js";
import { promptPassword } from "../utils/prompt.js";
import { handleError, printSuccess } from "../utils/output.js";

export function registerUnlockCommand(program: Command): void {
  program
    .command("unlock")
    .description("Unlock the vault")
    .option("--ttl <minutes>", "Session TTL in minutes", "15")
    .action(async (_options, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const password = await promptPassword();
        const engine = createEngine(vaultDir);
        try {
          await engine.unlock(password);
          printSuccess("Vault unlocked.");
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
