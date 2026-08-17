import type { Command } from "commander";
import { CertManager } from "@harpoc/cert-manager";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";
import { parseIntOption } from "../../utils/options.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

const MIN_PORT = 1;
const MAX_PORT = 65535;

interface CertRenewOptions {
  httpPort?: string;
  json?: boolean;
  token?: string;
}

export function registerCertRenewCommand(cert: Command): void {
  cert
    .command("renew <handle>")
    .description("Renew an ACME-issued certificate now against its stored account")
    .option("--http-port <port>", "Port for the http-01 challenge responder (default: 80)")
    .option("--json", "Output as JSON")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (handle: string, options: CertRenewOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        // The manager range-checks the port too; parsing here only turns a
        // non-numeric argument into a message naming the option, before the
        // vault opens.
        const httpPort =
          options.httpPort === undefined
            ? undefined
            : parseIntOption(options.httpPort, "http-port", MIN_PORT, MAX_PORT);

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "rotate",
            handle,
            options.token ?? process.env.HARPOC_TOKEN,
          );
          const secretId = await resolveSecretId(engine, handle);

          const manager = new CertManager(engine);
          // The caller threads into every engine read and the write, so
          // per-secret access policies apply to a token-bearing renewal (V1);
          // omitting it is the trusted local path the scheduler uses.
          const status = await manager.renewCertificate(secretId, {
            httpPort,
            caller: resolved?.caller,
          });

          if (options.json) {
            printJson(status);
          } else {
            printRecord({
              Handle: handle,
              Subject: status.subject,
              "Not after": formatTimestamp(status.not_after),
              "Renewal status": status.renewal_status,
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
