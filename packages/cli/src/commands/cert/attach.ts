import type { Command } from "commander";
import { AuditEventType } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine, resolveSecretId } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { readPemFile } from "./import.js";

interface CertAttachOptions {
  cert: string;
  chain?: string;
  json?: boolean;
  token?: string;
}

export function registerCertAttachCommand(cert: Command): void {
  cert
    .command("attach <handle>")
    .description("Attach an externally issued certificate to a pending cert csr secret")
    .requiredOption("--cert <path>", "Issued certificate PEM file (may contain the chain)")
    .option("--chain <path>", "Separate chain PEM file")
    .option("--json", "Output as JSON")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (handle: string, options: CertAttachOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        if (options.cert.trim() === "") {
          throw new Error("--cert requires a path to a certificate PEM file.");
        }
        if (options.chain !== undefined && options.chain.trim() === "") {
          throw new Error("--chain requires a path to a chain PEM file, or omit it entirely.");
        }
        // Public material, read before the vault opens: a mistyped path never unlocks it.
        const certificatePem = readPemFile(options.cert, "certificate");
        const chainPem =
          options.chain === undefined ? undefined : readPemFile(options.chain, "chain");

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
            AuditEventType.CERT_ISSUE,
          );

          await engine.updateCertificate(
            secretId,
            certificatePem,
            chainPem,
            { renewed: false, handle },
            resolved?.caller,
          );
          const status = engine.getCertificateStatus(secretId, resolved?.caller, handle);

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
