import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerOAuthStatusCommand(oauth: Command): void {
  oauth
    .command("status <handle>")
    .description("Show OAuth token health for a secret (no sensitive fields)")
    .option("--json", "Output as JSON")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (handle: string, options: { json?: boolean; token?: string }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "read",
            handle,
            options.token ?? process.env.HARPOC_TOKEN,
          );
          const secretId = await resolveSecretId(engine, handle);
          const status = engine.getOAuthTokenStatus(secretId, resolved?.caller);
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
              "Token endpoint auth": status.token_endpoint_auth_method,
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
