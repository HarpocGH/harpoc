import type { Command } from "commander";
import { createEngine, resolveVaultDir } from "../../utils/vault-loader.js";
import { promptPassword } from "../../utils/prompt.js";
import { handleError, printSuccess } from "../../utils/output.js";

export function registerUnlockKeyRevokeCommand(unlockKey: Command): void {
  unlockKey
    .command("revoke")
    .description(
      "Revoke the machine-bound unlock key after a master-password prompt: --unlock-key-file and --unlock-credential no longer unlock the vault",
    )
    .action(async (_options, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const password = await promptPassword();
        const engine = createEngine(vaultDir);
        try {
          await engine.unlock(password);
          await engine.revokeUnlockKey();
          printSuccess(
            "Unlock key revoked: --unlock-key-file and --unlock-credential no longer unlock this vault.",
          );
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
