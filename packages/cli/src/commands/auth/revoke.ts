import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printSuccess } from "../../utils/output.js";
import { restModeOf, runRestMode } from "../../utils/rest-mode.js";

export function registerAuthRevokeCommand(auth: Command): void {
  auth
    .command("revoke <jti>")
    .description(
      "Revoke an API token by its JTI (the issued-token registry supplies its expiry; an unknown JTI is refused)",
    )
    .action(async (jti: string, _options: Record<string, never>, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const rest = restModeOf(cmd);
        if (rest) {
          await runRestMode(rest, async (client) => {
            await client.revokeToken(jti);
            printSuccess(`Token revoked (${jti})`);
          });
          return;
        }
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          engine.revokeToken(jti);
          printSuccess(`Token revoked (${jti})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
