import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess, formatTimestamp } from "../../utils/output.js";

export function registerOAuthRefreshCommand(oauth: Command): void {
  oauth
    .command("refresh <handle>")
    .description("Refresh the OAuth access token now (explicit operator action)")
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: { json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const secretId = await resolveSecretId(engine, handle);
          const newExpiresAt = await engine.refreshOAuthToken(secretId);
          if (options.json) {
            printJson({ handle, new_expires_at: newExpiresAt });
          } else if (newExpiresAt === null) {
            printSuccess(`Token refreshed for ${handle} (provider returned no expiry)`);
          } else {
            printSuccess(
              `Token refreshed for ${handle} (expires ${formatTimestamp(newExpiresAt)})`,
            );
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
