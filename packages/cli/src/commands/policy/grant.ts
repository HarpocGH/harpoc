import type { Command } from "commander";
import type { Permission, PrincipalType } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printSuccess, printJson, printRecord } from "../../utils/output.js";

export function registerPolicyGrantCommand(policy: Command): void {
  policy
    .command("grant <handle>")
    .description("Grant an access policy on a secret")
    .requiredOption("--principal-type <type>", "Principal type (agent, tool, project, user)")
    .requiredOption("--principal-id <id>", "Principal identifier")
    .requiredOption("--permissions <perms>", "Comma-separated permissions")
    .option("--expires <minutes>", "Policy TTL in minutes")
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: { principalType: string; principalId: string; permissions: string; expires?: string; json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          // Resolve the handle to get the internal secret UUID
          const secretId = await resolveSecretId(engine, handle);

          const permissions = options.permissions.split(",").map((p) => p.trim()) as Permission[];
          const expiresAt = options.expires
            ? Date.now() + parseInt(options.expires, 10) * 60 * 1000
            : undefined;

          const policyResult = engine.grantPolicy(
            {
              secretId,
              principalType: options.principalType as PrincipalType,
              principalId: options.principalId,
              permissions,
              expiresAt,
            },
            "cli-user",
          );

          if (options.json) {
            printJson(policyResult);
          } else {
            printRecord({
              "Policy ID": policyResult.id,
              Secret: handle,
              Principal: `${policyResult.principal_type}:${policyResult.principal_id}`,
              Permissions: policyResult.permissions.join(", "),
              Expires: policyResult.expires_at ? new Date(policyResult.expires_at).toISOString() : "-",
            });
            printSuccess("Policy granted.");
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
