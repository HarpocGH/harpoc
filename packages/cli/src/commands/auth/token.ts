import type { Command } from "commander";
import type { Permission } from "@harpoc/shared";
import { MAX_TOKEN_TTL_MS, permissionSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord } from "../../utils/output.js";

export function registerAuthTokenCommand(auth: Command): void {
  auth
    .command("token")
    .description("Create a scoped API token")
    .option("--scope <permissions>", "Comma-separated permissions (list,read,use,create,rotate,revoke,admin)")
    .option("--ttl <minutes>", "Token TTL in minutes", "60")
    .option("--agent <name>", "Agent name (sets JWT subject)")
    .option("--project <name>", "Project scope for the token")
    .option("--secrets <names>", "Comma-separated secret names the token can access")
    .option("--json", "Output as JSON")
    .action(async (options: { scope?: string; ttl?: string; agent?: string; project?: string; secrets?: string; json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const scopeStrings = options.scope
            ? options.scope.split(",").map((s) => s.trim())
            : ["use", "list"];
          for (const s of scopeStrings) {
            const result = permissionSchema.safeParse(s);
            if (!result.success) {
              throw new Error(`Invalid permission: "${s}". Valid: list, read, use, create, rotate, revoke, admin`);
            }
          }
          const scope = scopeStrings as Permission[];

          const subject = options.agent ?? "cli-user";
          const maxTtlMinutes = Math.floor(MAX_TOKEN_TTL_MS / 60_000);
          const ttlMinutes = parseInt(options.ttl ?? "60", 10);
          if (isNaN(ttlMinutes) || ttlMinutes <= 0) {
            throw new Error("TTL must be a positive number of minutes");
          }
          if (ttlMinutes > maxTtlMinutes) {
            throw new Error(`TTL cannot exceed ${maxTtlMinutes} minutes (${maxTtlMinutes / 60}h)`);
          }
          const ttlMs = ttlMinutes * 60 * 1000;

          const token = engine.createToken(subject, scope, ttlMs);

          if (options.json) {
            printJson({
              token,
              subject,
              scope,
              ttl_minutes: parseInt(options.ttl ?? "60", 10),
              project: options.project ?? null,
              secrets: options.secrets ? options.secrets.split(",").map((s) => s.trim()) : null,
            });
          } else {
            printRecord({
              Token: token,
              Subject: subject,
              Scope: scope.join(", "),
              TTL: `${options.ttl ?? "60"} minutes`,
              Project: options.project ?? "-",
              Secrets: options.secrets ?? "-",
            });
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
