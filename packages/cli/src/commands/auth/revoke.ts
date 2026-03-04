import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printSuccess } from "../../utils/output.js";

function decodeTokenExp(token: string): number | undefined {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (typeof payload.exp === "number") return payload.exp;
  } catch {
    // Ignore decode errors
  }
  return undefined;
}

export function registerAuthRevokeCommand(auth: Command): void {
  auth
    .command("revoke <jti>")
    .description("Revoke an API token by its JTI")
    .option("--token <jwt>", "Full JWT token (used to extract expiry for accurate revocation)")
    .action(async (jti: string, options: { token?: string }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const expiresAt = options.token ? decodeTokenExp(options.token) : undefined;
          engine.revokeToken(jti, expiresAt);
          printSuccess(`Token revoked (${jti})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
