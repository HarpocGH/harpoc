import { readFileSync } from "node:fs";
import type { Command } from "commander";
import type { ConnectionConfig } from "@harpoc/shared";
import { connectionConfigSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";

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
  clear?: boolean;
  show?: boolean;
  delete?: boolean;
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
      "Pinned SSH known_hosts line (repeatable, replaces the stored list)",
      collect,
      [],
    )
    .option("--known-hosts-file <path>", "Path to a known_hosts file to pin (SSH)")
    .option("--clear", "Reset the whole config to empty before applying the other flags")
    .option("--show", "Show the current config instead of setting it")
    .option("--delete", "Remove the config")
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: ConnectionOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          if (options.delete) {
            const deleted = await engine.deleteConnectionConfig(handle);
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
            options.clear === true;
          if (options.show || !hasInput) {
            const current = await engine.getConnectionConfig(handle);
            printJson(current ?? null);
            return;
          }

          const current = await engine.getConnectionConfig(handle);
          const config = mergeConnectionConfig(current, options);

          const parsed = connectionConfigSchema.safeParse(config);
          if (!parsed.success) {
            throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
          }

          await engine.setConnectionConfig(handle, parsed.data);
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

  return config;
}
