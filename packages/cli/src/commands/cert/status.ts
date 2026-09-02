import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerCertStatusCommand(cert: Command): void {
  cert
    .command("status <handle>")
    .description("Show certificate health for a secret (no private key material)")
    .option("--json", "Output as JSON")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (handle: string, options: { json?: boolean; token?: string }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "read",
            handle,
            options.token ?? process.env.HARPOC_TOKEN,
          );
          const secretId = await resolveSecretId(engine, handle);
          const status = engine.getCertificateStatus(secretId, resolved?.caller, handle);
          if (options.json) {
            printJson(status);
          } else {
            printRecord({
              Handle: handle,
              Subject: status.subject,
              Issuer: status.issuer,
              "Not before": formatTimestamp(status.not_before),
              "Not after": formatTimestamp(status.not_after),
              "Auto renew": status.auto_renew ? "yes" : "no",
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
