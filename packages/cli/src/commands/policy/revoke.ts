import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printSuccess } from "../../utils/output.js";

export function registerPolicyRevokeCommand(policy: Command): void {
  policy
    .command("revoke <policy-id>")
    .description("Revoke an access policy")
    .action(async (policyId: string, _options: Record<string, unknown>, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          engine.revokePolicy(policyId);
          printSuccess(`Policy revoked (${policyId})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err);
      }
    });
}
