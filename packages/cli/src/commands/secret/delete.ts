import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { promptConfirm } from "../../utils/prompt.js";
import { handleError, printSuccess } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerSecretDeleteCommand(secret: Command): void {
  secret
    .command("delete <handle>")
    .description("Revoke and delete a secret")
    .option("--confirm", "Skip confirmation prompt")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(
      async (handle: string, options: { confirm?: boolean; token?: string }, cmd: Command) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          // Engine first (the set.ts precedent): a sealed vault and scope
          // refusal both precede the confirmation prompt.
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const resolved = resolveTokenCallerForHandle(
              engine,
              "revoke",
              handle,
              options.token ?? process.env.HARPOC_TOKEN,
            );
            if (!options.confirm) {
              const yes = await promptConfirm(`Delete secret ${handle}?`);
              if (!yes) {
                console.error("Aborted.");
                return;
              }
            }
            await engine.revokeSecret(handle, resolved?.caller);
            printSuccess(`Secret deleted (${handle})`);
          } finally {
            await engine.destroy();
          }
        } catch (err) {
          handleError(err);
        }
      },
    );
}
