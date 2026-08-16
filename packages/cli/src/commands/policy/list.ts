import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printTable, printJson, formatTimestamp } from "../../utils/output.js";
import type { ResolvedToken } from "../../utils/token-caller.js";
import {
  resolveTokenCaller,
  resolveTokenCallerForHandle,
  TOKEN_OPTION_DESCRIPTION,
} from "../../utils/token-caller.js";

export function registerPolicyListCommand(policy: Command): void {
  policy
    .command("list [handle]")
    .description("List access policies")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(
      async (
        handle: string | undefined,
        options: { token?: string; json?: boolean },
        cmd: Command,
      ) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const tokenValue = options.token ?? process.env.HARPOC_TOKEN;
            let resolved: ResolvedToken | undefined;
            let secretId: string | undefined;
            if (handle) {
              resolved = resolveTokenCallerForHandle(engine, "read", handle, tokenValue);
              secretId = await resolveSecretId(engine, handle);
            } else {
              resolved = resolveTokenCaller(engine, { permission: "read" }, tokenValue);
            }

            const policies = engine.listPolicies(secretId, resolved?.caller);

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
      },
    );
}
