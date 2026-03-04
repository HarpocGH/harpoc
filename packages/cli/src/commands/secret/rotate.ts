import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { promptSecret } from "../../utils/prompt.js";
import { handleError, printSuccess } from "../../utils/output.js";

export function registerSecretRotateCommand(secret: Command): void {
  secret
    .command("rotate <handle>")
    .description("Rotate a secret value")
    .action(async (handle: string, _options: Record<string, unknown>, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const newValue = await promptSecret("New secret value: ");
        if (!newValue) {
          console.error("Error: Secret value cannot be empty.");
          process.exit(1);
        }

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          await engine.rotateSecret(handle, new TextEncoder().encode(newValue));
          printSuccess(`Secret rotated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
