import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printTable, printJson, formatTimestamp } from "../../utils/output.js";

export function registerSecretListCommand(secret: Command): void {
  secret
    .command("list")
    .description("List secrets")
    .option("-p, --project <project>", "Filter by project")
    .option("-t, --type <type>", "Filter by type")
    .option("-s, --status <status>", "Filter by status")
    .option("--json", "Output as JSON")
    .action(async (options: { project?: string; type?: string; status?: string; json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          let secrets = engine.listSecrets(options.project);

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
    });
}
