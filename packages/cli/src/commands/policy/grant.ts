import type { Command } from "commander";
import type { Permission, PrincipalType } from "@harpoc/shared";
import { AuditEventType, VaultError, permissionSchema, principalTypeSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printSuccess, printJson, printRecord } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { parsePositiveInteger } from "../../utils/options.js";
import { restModeOf, runRestMode } from "../../utils/rest-mode.js";

interface GrantOptions {
  principalType: string;
  principalId: string;
  permissions: string;
  expires?: string;
  token?: string;
  json?: boolean;
}

/** The permission list, then the principal type; each refusal `INVALID_INPUT`. */
function parseGrantFlags(options: GrantOptions): {
  permissions: Permission[];
  principalType: PrincipalType;
} {
  const permStrings = options.permissions.split(",").map((p) => p.trim());
  for (const p of permStrings) {
    if (!permissionSchema.safeParse(p).success) {
      throw VaultError.invalidInput(
        `Invalid permission: "${p}". Valid: list, read, use, create, rotate, revoke, admin`,
      );
    }
  }
  const parsedType = principalTypeSchema.safeParse(options.principalType);
  if (!parsedType.success) {
    throw VaultError.invalidInput(
      `Invalid principal type: "${options.principalType}". Valid: agent, tool, project, user`,
    );
  }
  return { permissions: permStrings as Permission[], principalType: parsedType.data };
}

export function registerPolicyGrantCommand(policy: Command): void {
  policy
    .command("grant <handle>")
    .description("Grant an access policy on a secret")
    .requiredOption("--principal-type <type>", "Principal type (agent, tool, project, user)")
    .requiredOption("--principal-id <id>", "Principal identifier")
    .requiredOption("--permissions <perms>", "Comma-separated permissions")
    .option("--expires <minutes>", "Policy TTL in minutes")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: GrantOptions, cmd: Command) => {
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

        const rest = restModeOf(cmd);
        if (rest) {
          await runRestMode(rest, async (client) => {
            const { permissions, principalType } = parseGrantFlags(options);
            const policyResult = await client.grantPolicy(handle, {
              principal_type: principalType,
              principal_id: options.principalId,
              permissions,
              expires_at: expiresAt,
            });
            if (options.json) {
              printJson(policyResult);
            } else {
              printRecord({
                "Policy ID": policyResult.id,
                Secret: handle,
                Principal: `${policyResult.principal_type}:${policyResult.principal_id}`,
                Permissions: policyResult.permissions.join(", "),
                Expires: policyResult.expires_at
                  ? new Date(policyResult.expires_at).toISOString()
                  : "-",
              });
              printSuccess("Policy granted.");
            }
          });
          return;
        }

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "admin",
            handle,
            options.token ?? process.env.HARPOC_TOKEN,
          );

          // Resolve the handle to get the internal secret UUID
          const secretId = await resolveSecretId(
            engine,
            handle,
            resolved?.caller,
            AuditEventType.POLICY_GRANT,
          );

          const { permissions, principalType } = parseGrantFlags(options);

          const policyResult = engine.grantPolicy(
            {
              secretId,
              principalType,
              principalId: options.principalId,
              permissions,
              expiresAt,
            },
            resolved ? resolved.payload.sub : "cli-user",
            resolved?.caller,
          );

          if (options.json) {
            printJson(policyResult);
          } else {
            printRecord({
              "Policy ID": policyResult.id,
              Secret: handle,
              Principal: `${policyResult.principal_type}:${policyResult.principal_id}`,
              Permissions: policyResult.permissions.join(", "),
              Expires: policyResult.expires_at
                ? new Date(policyResult.expires_at).toISOString()
                : "-",
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
