import type { Command } from "commander";
import type { AuditEventType } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../utils/vault-loader.js";
import { handleError, printTable, printJson, formatTimestamp } from "../utils/output.js";

export function registerAuditCommand(program: Command): void {
  const audit = program
    .command("audit")
    .description("Query the audit log")
    .option("--secret <id>", "Filter by secret ID")
    .option("--event <type>", "Filter by event type")
    .option("--since <date>", "Filter events after date (ISO 8601)")
    .option("--limit <count>", "Maximum number of events", "50")
    .option("--json", "Output as JSON")
    .action(
      async (
        options: {
          secret?: string;
          event?: string;
          since?: string;
          limit?: string;
          json?: boolean;
        },
        cmd: Command,
      ) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const limit = options.limit ? parseInt(options.limit, 10) : 50;
            if (isNaN(limit) || limit <= 0) {
              throw new Error("--limit must be a positive number");
            }

            const since = options.since ? new Date(options.since).getTime() : undefined;
            if (since !== undefined && Number.isNaN(since)) {
              throw new Error("--since must be a valid date (e.g. 2026-07-01 or 2026-07-01T12:00:00Z)");
            }

            const events = engine.queryAudit({
              secretId: options.secret,
              eventType: options.event as AuditEventType | undefined,
              since,
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
      },
    );

  audit
    .command("verify")
    .description("Verify the audit log tamper-evidence chain")
    .option("--json", "Output as JSON")
    .action(async (options: { json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const result = engine.verifyAuditChain();
          if (options.json) {
            printJson(result);
          } else if (result.valid) {
            console.log(
              `Audit chain OK — ${result.checked} row(s) verified, ${result.legacy} legacy row(s) skipped.`,
            );
          } else {
            console.error(
              `Audit chain BROKEN at row ${result.firstBrokenId ?? "?"} — ` +
                `${result.checked} verified, ${result.legacy} legacy.`,
            );
          }
          if (!result.valid) {
            process.exitCode = 1;
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
