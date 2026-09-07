import { closeSync, existsSync, fchmodSync, openSync, unlinkSync, writeSync } from "node:fs";
import type { Command } from "commander";
import type { Permission } from "@harpoc/shared";
import {
  MAX_TOKEN_TTL_MS,
  VaultError,
  permissionSchema,
  tokenPrincipalTypeSchema,
} from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord } from "../../utils/output.js";

export function registerAuthTokenCommand(auth: Command): void {
  auth
    .command("token")
    .description("Create a scoped API token")
    .option(
      "--scope <permissions>",
      "Comma-separated permissions (list,read,use,create,rotate,revoke,admin)",
    )
    .option("--ttl <minutes>", "Token TTL in minutes", "60")
    .option("--agent <name>", "Agent name (sets JWT subject)")
    .option(
      "--principal-type <type>",
      "Principal type for per-secret policy matching (agent, tool, user)",
      "agent",
    )
    .option("--project <name>", "Project scope for the token")
    .option(
      "--secrets <patterns>",
      "Comma-separated secret names or patterns with * wildcards (e.g. db-*) the token can access",
    )
    .option("--label <text>", "Label for the issued token (shown in token listings)")
    .option("--out <file>", "Write the bare token to <file> (0600) instead of printing it")
    .option("--json", "Output as JSON")
    .action(
      async (
        options: {
          scope?: string;
          ttl?: string;
          agent?: string;
          principalType?: string;
          project?: string;
          secrets?: string;
          label?: string;
          out?: string;
          json?: boolean;
        },
        cmd: Command,
      ) => {
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
                throw new Error(
                  `Invalid permission: "${s}". Valid: list, read, use, create, rotate, revoke, admin`,
                );
              }
            }
            const scope = scopeStrings as Permission[];

            const subject = options.agent ?? "cli-user";

            const parsedPrincipalType = tokenPrincipalTypeSchema.safeParse(
              options.principalType ?? "agent",
            );
            if (!parsedPrincipalType.success) {
              throw new Error(
                `Invalid principal type: "${options.principalType}". Valid: agent, tool, user`,
              );
            }
            const principalType = parsedPrincipalType.data;
            const maxTtlMinutes = Math.floor(MAX_TOKEN_TTL_MS / 60_000);
            const ttlMinutes = parseInt(options.ttl ?? "60", 10);
            if (isNaN(ttlMinutes) || ttlMinutes <= 0) {
              throw new Error("TTL must be a positive number of minutes");
            }
            if (ttlMinutes > maxTtlMinutes) {
              throw new Error(
                `TTL cannot exceed ${maxTtlMinutes} minutes (${maxTtlMinutes / 60}h)`,
              );
            }
            const ttlMs = ttlMinutes * 60 * 1000;

            // Checked before the mint: a refused write must not leave a row in
            // the issued-token registry for a token nobody ever received. No
            // --force — the flag writes a credential, and silently replacing
            // one is how a live launch token gets orphaned.
            const out = options.out;
            if (out !== undefined && existsSync(out)) {
              throw VaultError.invalidInput(
                `--out ${out} already exists; remove it or choose another path`,
              );
            }
            // Opened before the mint as well (R3, 2026-09-07): 0600 at
            // creation, like the session file beside it — open(2) applies the
            // mode and umask can only tighten it — and "wx" (O_EXCL) refuses
            // any existing path, a symlink included, so the check above can be
            // neither raced nor redirected. A path that cannot be opened (a
            // missing directory, a permission) therefore mints nothing.
            const outFd = out === undefined ? undefined : openSync(out, "wx", 0o600);

            const project = options.project;
            const secrets = options.secrets
              ? options.secrets.split(",").map((s) => s.trim())
              : undefined;
            let token: string;
            try {
              token = engine.createToken(subject, scope, ttlMs, {
                project,
                secrets,
                principalType,
                label: options.label,
              });
            } catch (err) {
              if (out !== undefined && outFd !== undefined) {
                closeSync(outFd);
                try {
                  unlinkSync(out);
                } catch (unlinkErr) {
                  console.error(
                    `Warning: could not remove the empty ${out} after the token was refused (${unlinkErr instanceof Error ? unlinkErr.message : String(unlinkErr)})`,
                  );
                }
              }
              throw err;
            }

            if (out !== undefined && outFd !== undefined) {
              try {
                writeSync(outFd, token + "\n");
                // The POSIX chmod repair mirrors init.ts and is skipped on
                // win32, where the file inherits the directory ACL as the
                // vault does.
                if (process.platform !== "win32") {
                  try {
                    fchmodSync(outFd, 0o600);
                  } catch (err) {
                    console.error(
                      `Warning: could not restrict ${out} to owner-only access (${err instanceof Error ? err.message : String(err)})`,
                    );
                  }
                }
              } finally {
                closeSync(outFd);
              }
              console.error(`Token written to ${out}`);
            }

            if (options.json) {
              printJson({
                ...(options.out !== undefined ? { token_file: options.out } : { token }),
                subject,
                principal_type: principalType,
                scope,
                ttl_minutes: parseInt(options.ttl ?? "60", 10),
                project: options.project ?? null,
                secrets: options.secrets ? options.secrets.split(",").map((s) => s.trim()) : null,
                label: options.label ?? null,
              });
            } else {
              printRecord({
                ...(options.out !== undefined ? {} : { Token: token }),
                Subject: subject,
                "Principal type": principalType,
                Scope: scope.join(", "),
                TTL: `${options.ttl ?? "60"} minutes`,
                Project: options.project ?? "-",
                Secrets: options.secrets ?? "-",
                Label: options.label ?? "-",
              });
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
