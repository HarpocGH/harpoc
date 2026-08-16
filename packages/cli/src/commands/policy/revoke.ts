import type { Command } from "commander";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printSuccess } from "../../utils/output.js";
import type { ResolvedToken } from "../../utils/token-caller.js";
import {
  refuseEmptyToken,
  resolveTokenCallerForHandle,
  TOKEN_OPTION_DESCRIPTION,
} from "../../utils/token-caller.js";

export function registerPolicyRevokeCommand(policy: Command): void {
  policy
    .command("revoke <policy-id>")
    .description("Revoke an access policy")
    .option("--secret <handle>", "The secret the policy belongs to (required with --token)")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(
      async (policyId: string, options: { secret?: string; token?: string }, cmd: Command) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const tokenValue = options.token ?? process.env.HARPOC_TOKEN;
            refuseEmptyToken(tokenValue);
            if (tokenValue !== undefined && !options.secret) {
              throw new Error(
                "--secret <handle> is required when using --token: token scope is checked against the secret the policy belongs to.",
              );
            }
            let resolved: ResolvedToken | undefined;
            if (options.secret) {
              resolved = resolveTokenCallerForHandle(engine, "admin", options.secret, tokenValue);
              const secretId = await resolveSecretId(engine, options.secret);
              // Membership check mirrors REST DELETE /:handle/policies/:policyId
              // (cross-secret IDOR guard); deliberately caller-less — the
              // caller's own gate is the admin check inside revokePolicy.
              const policies = engine.listPolicies(secretId);
              if (!policies.some((p) => p.id === policyId)) {
                throw new VaultError(
                  ErrorCode.POLICY_NOT_FOUND,
                  "Policy not found for this secret",
                );
              }
            }
            engine.revokePolicy(policyId, resolved?.caller);
            printSuccess(`Policy revoked (${policyId})`);
          } finally {
            await engine.destroy();
          }
        } catch (err) {
          handleError(err);
        }
      },
    );
}
