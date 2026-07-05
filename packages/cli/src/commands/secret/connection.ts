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

interface ConnectionOptions {
  dbTls?: string;
  dbCaFile?: string;
  dbServername?: string;
  knownHost?: string[];
  knownHostsFile?: string;
  show?: boolean;
  delete?: boolean;
  json?: boolean;
}

export function registerSecretConnectionCommand(secret: Command): void {
  secret
    .command("connection <handle>")
    .description(
      "Configure a secret's endpoint-authentication pins — database TLS policy and SSH host keys (trusted admin path)",
    )
    .option("--db-tls <mode>", "Database TLS mode: require | disable")
    .option("--db-ca-file <path>", "Path to a CA certificate PEM (database TLS)")
    .option("--db-servername <name>", "TLS servername override (database)")
    .option("--known-host <line>", "Pinned SSH known_hosts line (repeatable)", collect, [])
    .option("--known-hosts-file <path>", "Path to a known_hosts file to pin (SSH)")
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

          const config = buildConfig(options);
          const hasInput = config.database !== undefined || config.ssh !== undefined;
          if (options.show || !hasInput) {
            const current = await engine.getConnectionConfig(handle);
            printJson(current ?? null);
            return;
          }

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

function buildConfig(options: ConnectionOptions): ConnectionConfig {
  const config: ConnectionConfig = {};

  if (options.dbTls || options.dbCaFile || options.dbServername) {
    config.database = {
      tls_mode: options.dbTls as "require" | "disable" | undefined,
      ca_pem: options.dbCaFile ? readFileSync(options.dbCaFile, "utf8") : undefined,
      servername: options.dbServername,
    };
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
  }

  return config;
}
