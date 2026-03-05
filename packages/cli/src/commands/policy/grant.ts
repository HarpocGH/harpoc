import type { Command } from "commander";
import type { Permission, PrincipalType } from "@harpoc/shared";
import { permissionSchema } from "@harpoc/shared";
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

          const permStrings = options.permissions.split(",").map((p) => p.trim());
          for (const p of permStrings) {
            const result = permissionSchema.safeParse(p);
            if (!result.success) {
              throw new Error(`Invalid permission: "${p}". Valid: list, read, use, create, rotate, revoke, admin`);
            }
          }
          const permissions = permStrings as Permission[];

          const expiresMinutes = options.expires ? parseInt(options.expires, 10) : undefined;
          if (expiresMinutes !== undefined && (isNaN(expiresMinutes) || expiresMinutes <= 0)) {
            throw new Error("--expires must be a positive number of minutes");
          }
          const expiresAt = expiresMinutes !== undefined
            ? Date.now() + expiresMinutes * 60 * 1000
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
