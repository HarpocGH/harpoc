import type { Command } from "commander";
import type { Permission } from "@harpoc/shared";
import { AuditEventType, VaultError, permissionSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import {
  handleError,
  printSuccess,
  printJson,
  printRecord,
  formatTimestamp,
} from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { parsePositiveInteger } from "../../utils/options.js";

interface PermissionsOptions {
  permissions?: string;
  clear?: boolean;
  expires?: string;
  token?: string;
  json?: boolean;
}

export function registerAgentPermissionsCommand(agent: Command): void {
  agent
    .command("permissions <name> <handle>")
    .description("Set one cell of the permission matrix (agent x secret)")
    .option("--permissions <perms>", "Comma-separated permissions")
    .option("--clear", "Clear the agent's permissions on this secret")
    .option("--expires <minutes>", "Grant TTL in minutes")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (name: string, handle: string, options: PermissionsOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const expiresMinutes =
          options.expires !== undefined
            ? parsePositiveInteger(
                options.expires,
                "--expires must be a positive number of minutes",
              )
            : undefined;
        const expiresAt =
          expiresMinutes !== undefined ? Date.now() + expiresMinutes * 60 * 1000 : undefined;

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "admin",
            handle,
            options.token ?? process.env.HARPOC_TOKEN,
          );

          if (options.permissions !== undefined && options.clear) {
            throw VaultError.invalidInput("--permissions and --clear are mutually exclusive");
          }
          if (options.permissions === undefined && !options.clear) {
            throw VaultError.invalidInput(
              "one of --permissions or --clear is required (an empty cell is never written)",
            );
          }
          // A cleared cell holds no grant to expire: refused, not dropped.
          if (options.clear && options.expires !== undefined) {
            throw VaultError.invalidInput("--expires cannot be combined with --clear");
          }

          const permStrings =
            options.permissions === undefined
              ? []
              : options.permissions.split(",").map((p) => p.trim());
          for (const p of permStrings) {
            const parsed = permissionSchema.safeParse(p);
            if (!parsed.success) {
              throw VaultError.invalidInput(
                `Invalid permission: "${p}". Valid: list, read, use, create, rotate, revoke, admin`,
              );
            }
          }
          const permissions = permStrings as Permission[];

          const secretId = await resolveSecretId(
            engine,
            handle,
            resolved?.caller,
            AuditEventType.POLICY_GRANT,
          );
          const result = engine.setAgentPermissions(
            name,
            secretId,
            permissions,
            expiresAt,
            resolved ? resolved.payload.sub : "cli-user",
            resolved?.caller,
          );

          if (options.json) {
            printJson(result);
          } else {
            printRecord({
              Agent: name,
              Secret: handle,
              Permissions: result.policy ? result.policy.permissions.join(", ") : null,
              Expires: formatTimestamp(result.policy?.expires_at ?? null),
            });
            if (result.gated_before !== result.gated_after) {
              console.error(
                result.gated_after
                  ? `Note: ${handle} received its first grant — until now no agent or tool token could reach it.`
                  : `Note: ${handle} has no grants left — no agent or tool token can reach it until one is written.`,
              );
            }
            printSuccess(permissions.length > 0 ? "Permissions set." : "Permissions cleared.");
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
