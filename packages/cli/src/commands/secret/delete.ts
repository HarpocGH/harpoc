import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { promptConfirm } from "../../utils/prompt.js";
import { handleError, printSuccess } from "../../utils/output.js";

export function registerSecretDeleteCommand(secret: Command): void {
  secret
    .command("delete <handle>")
    .description("Revoke and delete a secret")
    .option("--confirm", "Skip confirmation prompt")
    .action(async (handle: string, options: { confirm?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        if (!options.confirm) {
          const yes = await promptConfirm(`Delete secret ${handle}?`);
          if (!yes) {
            console.error("Aborted.");
            process.exit(0);
          }
        }

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          await engine.revokeSecret(handle);
          printSuccess(`Secret deleted (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
