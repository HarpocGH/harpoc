import type { Command } from "commander";
import { CertManager } from "@harpoc/cert-manager";
import { AuditEventType } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";
import { parseIntOption } from "../../utils/options.js";
import { MAX_PORT, MIN_PORT } from "../../utils/option-bounds.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { restModeOf, restModeUnsupported, runRestMode } from "../../utils/rest-mode.js";

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

        const rest = restModeOf(cmd);
        if (rest) {
          // POST /certificates/:handle/renew takes no port: the server's CertManager answers
          // the http-01 challenge on its default port 80.
          if (httpPort !== undefined) throw restModeUnsupported("cert renew --http-port");
          await runRestMode(rest, async (client) => {
            const status = await client.renewCertificate(handle);
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
          });
          return;
        }

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "rotate",
            handle,
            options.token ?? process.env.HARPOC_TOKEN,
          );
          const secretId = await resolveSecretId(
            engine,
            handle,
            resolved?.caller,
            AuditEventType.CERT_RENEW,
          );

          const manager = new CertManager(engine);
          // The caller threads into every engine read and the write, so
          // per-secret access policies apply to a token-bearing renewal (V1);
          // omitting it is the trusted local path the scheduler uses.
          const status = await manager.renewCertificate(secretId, {
            httpPort,
            caller: resolved?.caller,
            handle,
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
