import type { Command } from "commander";
import { VaultError, matchesSecretNameScope } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printTable, printJson, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerSecretListCommand(secret: Command): void {
  secret
    .command("list")
    .description("List secrets")
    .option("-p, --project <project>", "Filter by project")
    .option("-t, --type <type>", "Filter by type")
    .option("-s, --status <status>", "Filter by status")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(
      async (
        options: {
          project?: string;
          type?: string;
          status?: string;
          token?: string;
          json?: boolean;
        },
        cmd: Command,
      ) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const resolved = resolveTokenCaller(
              engine,
              { permission: "list" },
              options.token ?? process.env.HARPOC_TOKEN,
            );
            // H4: for a token-bearing call, absent and empty are the same request (REST
            // parity). Tokenless, an explicit --project "" keeps its fail-closed empty
            // filter exactly as before token support.
            const project = resolved ? options.project || undefined : options.project;
            if (resolved?.payload.project && project && project !== resolved.payload.project) {
              throw VaultError.accessDenied(
                `Token is scoped to project: ${resolved.payload.project}`,
              );
            }
            const effectiveProject = project ?? resolved?.payload.project;
            let secrets = engine.listSecrets(effectiveProject, resolved?.caller);
            const namePatterns = resolved?.payload.secrets;
            if (namePatterns?.length) {
              secrets = secrets.filter((s) => matchesSecretNameScope(s.name, namePatterns));
            }

            if (options.type) {
              secrets = secrets.filter((s) => s.type === options.type);
            }
            if (options.status) {
              secrets = secrets.filter((s) => s.status === options.status);
            }

            if (options.json) {
              printJson(secrets);
            } else {
              const rows = secrets.map((s) => ({
                Handle: s.handle,
                Name: s.name,
                Type: s.type,
                Project: s.project ?? "-",
                Status: s.status,
                Version: s.version,
                Updated: formatTimestamp(s.updatedAt),
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
