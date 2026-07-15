import type { Command } from "commander";
import {
  resolveVaultDir,
  loadUnlockedEngine,
  resolveSecretId,
} from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";

export function registerOAuthStatusCommand(oauth: Command): void {
  oauth
    .command("status <handle>")
    .description("Show OAuth token health for a secret (no sensitive fields)")
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: { json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const secretId = await resolveSecretId(engine, handle);
          const status = engine.getOAuthTokenStatus(secretId);
          if (options.json) {
            printJson(status);
          } else {
            printRecord({
              Handle: handle,
              Provider: status.provider,
              "Access token": status.has_access_token ? "yes" : "no",
              "Token expires": formatTimestamp(status.access_token_expires_at),
              "Refresh token": status.has_refresh_token ? "yes" : "no",
              "Last refreshed": formatTimestamp(status.last_refreshed_at),
              "Refresh status": status.refresh_status,
              "Token endpoint auth": status.token_endpoint_auth_method ?? "client_secret_post",
            });
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
