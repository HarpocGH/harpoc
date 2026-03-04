import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printTable, printJson, formatTimestamp } from "../../utils/output.js";

export function registerPolicyListCommand(policy: Command): void {
  policy
    .command("list [handle]")
    .description("List access policies")
    .option("--json", "Output as JSON")
    .action(async (handle: string | undefined, options: { json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          // If a handle is provided, resolve it to the internal secret UUID
          let secretId: string | undefined;
          if (handle) {
            secretId = await resolveSecretId(engine, handle);
          }

          const policies = engine.listPolicies(secretId);

          if (options.json) {
            printJson(policies);
          } else {
            const rows = policies.map((p) => ({
              ID: p.id.slice(0, 8) + "...",
              Secret: p.secret_id.slice(0, 12) + "...",
              Principal: `${p.principal_type}:${p.principal_id}`,
              Permissions: p.permissions.join(","),
              Created: formatTimestamp(p.created_at),
              Expires: formatTimestamp(p.expires_at),
            }));
            printTable(rows);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
