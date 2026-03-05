import type { Command } from "commander";
import type { AuditEventType } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../utils/vault-loader.js";
import { handleError, printTable, printJson, formatTimestamp } from "../utils/output.js";

export function registerAuditCommand(program: Command): void {
  program
    .command("audit")
    .description("Query the audit log")
    .option("--secret <id>", "Filter by secret ID")
    .option("--event <type>", "Filter by event type")
    .option("--since <date>", "Filter events after date (ISO 8601)")
    .option("--limit <count>", "Maximum number of events", "50")
    .option("--json", "Output as JSON")
    .action(async (options: { secret?: string; event?: string; since?: string; limit?: string; json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const limit = options.limit ? parseInt(options.limit, 10) : 50;
          if (isNaN(limit) || limit <= 0) {
            throw new Error("--limit must be a positive number");
          }

          const events = engine.queryAudit({
            secretId: options.secret,
            eventType: options.event as AuditEventType | undefined,
            since: options.since ? new Date(options.since).getTime() : undefined,
            limit,
          });

          if (options.json) {
            printJson(events);
          } else {
            const rows = events.map((e) => ({
              ID: e.id,
              Time: formatTimestamp(e.timestamp),
              Event: e.event_type,
              Secret: e.secret_id ?? "-",
              Session: e.session_id ? e.session_id.slice(0, 8) + "..." : "-",
              Success: e.success ? "yes" : "no",
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
