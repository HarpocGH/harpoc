import { readFileSync } from "node:fs";
import type { Command } from "commander";
import type { ConnectionConfig, MailConnectionConfig } from "@harpoc/shared";
import { connectionConfigSchema, VaultError } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

export interface ConnectionOptions {
  dbTls?: string;
  dbCaFile?: string;
  dbServername?: string;
  knownHost?: string[];
  knownHostsFile?: string;
  /** Mail TLS opt-out (audited); honored for the implicit-TLS SMTP leg only — imap and smtp starttls actions refuse it fail-closed. */
  mailNoTls?: boolean;
  /** Path to a CA certificate PEM to pin the mail TLS connection to. */
  mailCa?: string;
  clear?: boolean;
  show?: boolean;
  delete?: boolean;
  token?: string;
  json?: boolean;
}

export function registerSecretConnectionCommand(secret: Command): void {
  secret
    .command("connection <handle>")
    .description(
      "Configure a secret's endpoint-authentication pins — database TLS policy and SSH host keys (trusted admin path); omitted flags keep their stored values",
    )
    .option("--db-tls <mode>", "Database TLS mode: require | disable")
    .option("--db-ca-file <path>", "Path to a CA certificate PEM (database TLS)")
    .option("--db-servername <name>", "TLS servername override (database)")
    .option(
      "--known-host <line>",
      "Pinned SSH known_hosts line (repeatable, replaces the stored list) — a non-22 port is pinned as `[host]:port`",
      collect,
      [],
    )
    .option("--known-hosts-file <path>", "Path to a known_hosts file to pin (SSH)")
    .option(
      "--mail-no-tls",
      "Opt out of TLS for mail (SMTP/IMAP); honored for the implicit-TLS SMTP leg only — imap and smtp starttls actions refuse this fail-closed",
    )
    .option(
      "--mail-ca <path>",
      "Path to a CA certificate PEM (mail TLS); also clears --mail-no-tls",
    )
    .option("--clear", "Reset the whole config to empty before applying the other flags")
    .option("--show", "Show the current config instead of setting it")
    .option("--delete", "Remove the config")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: ConnectionOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const tokenValue = options.token ?? process.env.HARPOC_TOKEN;

          if (options.delete) {
            const resolved = resolveTokenCallerForHandle(engine, "rotate", handle, tokenValue);
            const deleted = await engine.deleteConnectionConfig(handle, resolved?.caller);
            printSuccess(
              deleted
                ? `Connection config removed (${handle})`
                : `No connection config set (${handle})`,
            );
            return;
          }

          const hasInput =
            options.dbTls !== undefined ||
            options.dbCaFile !== undefined ||
            options.dbServername !== undefined ||
            (options.knownHost?.length ?? 0) > 0 ||
            options.knownHostsFile !== undefined ||
            options.mailNoTls === true ||
            options.mailCa !== undefined ||
            options.clear === true;
          if (options.show || !hasInput) {
            const resolved = resolveTokenCallerForHandle(engine, "read", handle, tokenValue);
            const current = await engine.getConnectionConfig(handle, resolved?.caller);
            printJson(current ?? null);
            return;
          }

          const resolved = resolveTokenCallerForHandle(engine, "rotate", handle, tokenValue);
          // The merge read is the command's own mechanics, deliberately
          // caller-less (its result never reaches the caller); the caller's
          // gate is the rotate check inside setConnectionConfig.
          const current = await engine.getConnectionConfig(handle);
          const config = mergeConnectionConfig(current, options);

          const parsed = connectionConfigSchema.safeParse(config);
          if (!parsed.success) {
            throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
          }

          await engine.setConnectionConfig(handle, parsed.data, resolved?.caller);
          printSuccess(`Connection config updated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}

/**
 * Merge the provided flags into the current config. Fields the caller omits
 * keep their stored values — per field within the database group, so e.g.
 * `--db-tls` alone cannot silently drop a pinned CA (`ca_pem`) or the SSH
 * `known_hosts`; a downgrade of an endpoint-auth pin must be explicit.
 * Provided `--known-host`/`--known-hosts-file` flags replace the stored SSH
 * list. `--clear` starts from an empty config instead of the stored one.
 */
export function mergeConnectionConfig(
  current: ConnectionConfig | null | undefined,
  options: ConnectionOptions,
): ConnectionConfig {
  const base = options.clear ? undefined : (current ?? undefined);
  const config: ConnectionConfig = {};

  const database = {
    tls_mode: (options.dbTls as "require" | "disable" | undefined) ?? base?.database?.tls_mode,
    ca_pem: options.dbCaFile ? readFileSync(options.dbCaFile, "utf8") : base?.database?.ca_pem,
    servername: options.dbServername ?? base?.database?.servername,
  };
  if (
    database.tls_mode !== undefined ||
    database.ca_pem !== undefined ||
    database.servername !== undefined
  ) {
    config.database = database;
  }

  const knownHosts = [...(options.knownHost ?? [])];
  if (options.knownHostsFile) {
    for (const line of readFileSync(options.knownHostsFile, "utf8").split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.length > 0 && !trimmed.startsWith("#")) knownHosts.push(trimmed);
    }
  }
  if (knownHosts.length > 0) {
    config.ssh = { known_hosts: knownHosts };
  } else if (base?.ssh) {
    config.ssh = base.ssh;
  }

  const mail = mergeMailConfig(base?.mail, options);
  if (mail) {
    config.mail = mail;
  }

  return config;
}

/**
 * Mirrors the database group's per-field merge for the single `tls` field
 * mail carries: `--mail-no-tls` (opt out) and `--mail-ca` (pin a CA, and —
 * since it means "use TLS" — clears a stored opt-out) are mutually
 * exclusive on one invocation, refused rather than silently picking one, the
 * same "a config the vault cannot honor refuses" convention `cert issue`'s
 * `--dns`+`--http-port` refusal follows. Neither flag present carries the
 * stored `tls` value through untouched, including a stored opt-out.
 */
function mergeMailConfig(
  base: MailConnectionConfig | undefined,
  options: ConnectionOptions,
): MailConnectionConfig | undefined {
  const noTlsGiven = options.mailNoTls === true;
  const caGiven = options.mailCa !== undefined;
  if (noTlsGiven && caGiven) {
    throw VaultError.invalidInput("--mail-no-tls and --mail-ca cannot be combined");
  }
  if (!noTlsGiven && !caGiven) {
    return base;
  }

  if (noTlsGiven) {
    return { tls: false };
  }

  const ca = options.mailCa ? readFileSync(options.mailCa, "utf8") : undefined;
  return { tls: ca !== undefined ? { ca } : {} };
}
