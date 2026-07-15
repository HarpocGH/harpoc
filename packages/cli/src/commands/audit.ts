import { readFileSync, writeFileSync } from "node:fs";
import type { Command } from "commander";
import type { AuditChainAnchor, AuditEventType } from "@harpoc/shared";
import { auditChainAnchorSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../utils/vault-loader.js";
import { handleError, printTable, printJson, formatTimestamp } from "../utils/output.js";

const OFF_HOST_GUIDANCE =
  "Store this anchor OFF-HOST (another machine, a sync target the attacker cannot write, or paper).\n" +
  "An attacker who can modify the vault database can likely also modify files beside it — " +
  "an anchor on the same disk detects nothing.";

function readAnchorFile(path: string): AuditChainAnchor {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new Error(`Cannot read anchor file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Anchor file is not valid JSON: ${path}`);
  }
  const result = auditChainAnchorSchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(
      `Not a valid harpoc audit anchor (expected format "harpoc-audit-anchor/1"): ${path}`,
    );
  }
  return result.data;
}

function tailLine(tail: AuditChainAnchor | null): string {
  if (!tail) return "Tail link: none (no chained audit rows).";
  return `Tail link: row ${tail.last_id} · hmac ${tail.row_hmac} · ${formatTimestamp(tail.timestamp)}`;
}

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
              throw new Error(
                "--since must be a valid date (e.g. 2026-07-01 or 2026-07-01T12:00:00Z)",
              );
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
    .command("anchor")
    .description("Export the audit-chain tail link for off-host storage")
    .option("--out <file>", "Write the anchor to a file instead of stdout")
    .option("--json", "Output as JSON (the default output is already JSON)")
    .action(async (options: { out?: string; json?: boolean }, cmd: Command) => {
      // The parent `audit` command declares --json too, and commander binds a
      // post-subcommand --json to the parent — read it through the merged view.
      const json = Boolean(options.json ?? cmd.optsWithGlobals().json);
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const anchor = engine.getAuditChainTail();
          if (!anchor) {
            throw new Error("No chained audit rows to anchor yet.");
          }
          const payload = JSON.stringify(anchor, null, 2);
          if (options.out) {
            writeFileSync(options.out, payload + "\n", "utf8");
            console.error(`Anchor written to ${options.out} (row ${anchor.last_id}).`);
          } else {
            console.log(payload);
          }
          console.error(OFF_HOST_GUIDANCE);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, json);
      }
    });

  audit
    .command("verify")
    .description("Verify the audit log tamper-evidence chain")
    .option(
      "--anchor <file>",
      "Also check the chain against a previously exported anchor (detects tail truncation and rollback)",
    )
    .option("--json", "Output as JSON")
    .action(async (options: { anchor?: string; json?: boolean }, cmd: Command) => {
      // Same parent/child --json collision as `audit anchor` — use the merged view.
      const json = Boolean(options.json ?? cmd.optsWithGlobals().json);
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const anchor = options.anchor ? readAnchorFile(options.anchor) : undefined;
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const result = engine.verifyAuditChain(anchor ? { anchor } : undefined);
          if (json) {
            printJson(result);
          } else {
            console.log(tailLine(result.tail));
            // Chain and anchor are independent signals — report both, always.
            if (result.firstBrokenId === null) {
              console.log(
                `Audit chain OK — ${result.checked} row(s) verified, ${result.legacy} legacy row(s) skipped.`,
              );
            } else {
              console.error(
                `Audit chain BROKEN at row ${result.firstBrokenId} — ` +
                  `${result.checked} verified, ${result.legacy} legacy.`,
              );
            }
            if (result.anchor) {
              if (result.anchor.status === "ok") {
                console.log(`Anchor OK — row ${result.anchor.lastId} intact.`);
              } else {
                console.error(
                  `Audit chain FAILS the anchor check — anchored row ${result.anchor.lastId} ` +
                    `${result.anchor.status === "row_missing" ? "is missing" : "was altered"}: ` +
                    "the newest rows were deleted or the database was rolled back.",
                );
              }
            }
          }
          if (!result.valid) {
            process.exitCode = 1;
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, json);
      }
    });
}
