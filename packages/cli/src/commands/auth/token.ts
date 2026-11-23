import {
  closeSync,
  fchmodSync,
  lstatSync,
  openSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import type { Command } from "commander";
import type { Permission } from "@harpoc/shared";
import {
  ErrorCode,
  MAX_TOKEN_TTL_MS,
  VaultError,
  permissionSchema,
  tokenPrincipalTypeSchema,
} from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord } from "../../utils/output.js";
import { parsePositiveInteger } from "../../utils/options.js";

function assertTokenOut(out: string): void {
  if (out.trim() === "") throw VaultError.invalidInput("--out: empty path");
  if (out.startsWith("-")) {
    throw VaultError.invalidInput(
      "--out: a flag, not a path (give a path that starts with a dash as ./-name)",
    );
  }
  const parent = dirname(resolve(out));
  let isDirectory = false;
  try {
    isDirectory = statSync(parent).isDirectory();
  } catch {
    // Refused below with the path, never the errno's text.
  }
  if (!isDirectory) throw VaultError.invalidInput(`--out: no such directory: ${parent}`);
  let exists: boolean;
  try {
    exists = lstatSync(out, { throwIfNoEntry: false }) !== undefined;
  } catch {
    throw VaultError.invalidInput(`--out: cannot check ${out} (is its directory searchable?)`);
  }
  if (exists) {
    throw VaultError.invalidInput(`--out: ${out} exists; the token is written to a new file only`);
  }
}

function errnoCode(err: unknown): string {
  const code = err instanceof Error ? (err as NodeJS.ErrnoException).code : undefined;
  return code ?? "unknown error";
}

function jtiOf(token: string): string {
  let jti: unknown;
  try {
    const payload = token.split(".")[1] ?? "";
    jti = (JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { jti?: unknown }).jti;
  } catch {
    jti = undefined;
  }
  if (typeof jti !== "string" || jti === "") {
    throw new VaultError(ErrorCode.INTERNAL_ERROR, "auth token: the minted token carries no jti");
  }
  return jti;
}

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
          const maxTtlMinutes = Math.floor(MAX_TOKEN_TTL_MS / 60_000);
          const ttlMinutes = parsePositiveInteger(
            options.ttl ?? "60",
            "TTL must be a positive number of minutes",
          );
          if (ttlMinutes > maxTtlMinutes) {
            throw VaultError.invalidInput(
              `TTL cannot exceed ${maxTtlMinutes} minutes (${maxTtlMinutes / 60}h)`,
            );
          }
          const ttlMs = ttlMinutes * 60 * 1000;

          const scopeStrings = options.scope
            ? options.scope.split(",").map((s) => s.trim())
            : ["use", "list"];
          for (const s of scopeStrings) {
            const result = permissionSchema.safeParse(s);
            if (!result.success) {
              throw VaultError.invalidInput(
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
            throw VaultError.invalidInput(
              `Invalid principal type: "${options.principalType}". Valid: agent, tool, user`,
            );
          }
          const principalType = parsedPrincipalType.data;
          // Checked before the vault opens, so before the mint: a refused write
          // must not leave a row in the issued-token registry for a token nobody
          // ever received. No --force — the flag writes a credential, and
          // silently replacing one is how a live launch token gets orphaned.
          const out = options.out;
          if (out !== undefined) assertTokenOut(out);

          const engine = await loadUnlockedEngine(vaultDir);
          try {
            // Opened before the mint as well (R3, 2026-09-07): 0600 at
            // creation, like the session file beside it — open(2) applies the
            // mode and umask can only tighten it — and "wx" (O_EXCL) refuses
            // any existing path, a symlink included, so the check before the
            // vault opened can be neither raced nor redirected. A path that
            // cannot be opened (a directory gone since that check, a
            // permission) therefore mints nothing.
            let outFd: number | undefined;
            if (out !== undefined) {
              try {
                outFd = openSync(out, "wx", 0o600);
              } catch (err) {
                throw new VaultError(
                  ErrorCode.FILE_IO_ERROR,
                  `could not write the token file ${out} (${errnoCode(err)})`,
                );
              }
            }

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
                try {
                  closeSync(outFd);
                } catch {
                  // The refusal is what is reported; a file left behind is warned of below.
                }
                try {
                  unlinkSync(out);
                } catch (unlinkErr) {
                  console.error(
                    `Warning: could not remove the empty ${out} after the token was refused (${errnoCode(unlinkErr)})`,
                  );
                }
              }
              throw err;
            }
            const jti = jtiOf(token);

            if (out !== undefined && outFd !== undefined) {
              let failedWith: string | undefined;
              try {
                const bytes = Buffer.from(token + "\n", "utf8");
                if (writeSync(outFd, bytes) !== bytes.length) {
                  failedWith = "short write";
                } else if (process.platform !== "win32") {
                  // The POSIX chmod repair mirrors init.ts and is skipped on
                  // win32, where the file inherits the directory ACL as the
                  // vault does.
                  try {
                    fchmodSync(outFd, 0o600);
                  } catch (err) {
                    console.error(
                      `Warning: could not restrict ${out} to owner-only access (${errnoCode(err)})`,
                    );
                  }
                }
              } catch (err) {
                failedWith = errnoCode(err);
              }
              try {
                closeSync(outFd);
              } catch (err) {
                failedWith ??= errnoCode(err);
              }
              if (failedWith !== undefined) {
                try {
                  engine.revokeToken(jti);
                } catch (err) {
                  const code = err instanceof VaultError ? err.code : "unknown error";
                  console.error(
                    `Warning: the token ${jti} could not be revoked (${code}); revoke it with: harpoc auth revoke ${jti}`,
                  );
                }
                try {
                  unlinkSync(out);
                } catch (err) {
                  console.error(
                    `Warning: could not remove ${out} after the failed write (${errnoCode(err)})`,
                  );
                }
                throw new VaultError(
                  ErrorCode.FILE_IO_ERROR,
                  `could not write the token file ${out} (${failedWith})`,
                );
              }
              console.error(`Token written to ${out}`);
            }

            if (options.json) {
              printJson({
                ...(options.out !== undefined ? { token_file: options.out } : { token }),
                jti,
                subject,
                principal_type: principalType,
                scope,
                ttl_minutes: ttlMinutes,
                project: options.project ?? null,
                secrets: options.secrets ? options.secrets.split(",").map((s) => s.trim()) : null,
                label: options.label ?? null,
              });
            } else {
              printRecord({
                ...(options.out !== undefined ? {} : { Token: token }),
                JTI: jti,
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
