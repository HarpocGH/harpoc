import { readFileSync, statSync } from "node:fs";
import type { Command } from "commander";
import { wipeBuffer } from "@harpoc/core";
import { CertManager } from "@harpoc/cert-manager";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord } from "../../utils/output.js";
import { parseIntOption } from "../../utils/options.js";
import { MAX_SECRET_FILE_BYTES, resolveSecretValue } from "../../utils/secret-value.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

const MIN_RENEW_BEFORE_DAYS = 1;
const MAX_RENEW_BEFORE_DAYS = 3650;

interface CertImportOptions {
  key: string;
  cert: string;
  chain?: string;
  project?: string;
  autoRenew?: boolean;
  renewBeforeDays: string;
  json?: boolean;
  token?: string;
}

/**
 * Read public certificate material. Unlike the private key this is not secret,
 * so it takes the plain read path — but it is read *first*, so a mistyped
 * certificate path fails before the key file is touched and before an
 * encrypted key can prompt for its passphrase.
 */
function readPemFile(path: string, label: string): string {
  let size: number;
  try {
    const stat = statSync(path);
    if (!stat.isFile()) throw new Error("not a file");
    size = stat.size;
  } catch {
    throw new Error(`Cannot read ${label} file: ${path}`);
  }
  if (size > MAX_SECRET_FILE_BYTES) {
    throw new Error(`The ${label} file exceeds the 1 MiB limit: ${path}`);
  }
  let pem: string;
  try {
    pem = readFileSync(path, "utf8");
  } catch {
    throw new Error(`Cannot read ${label} file: ${path}`);
  }
  if (pem.trim() === "") throw new Error(`The ${label} file is empty: ${path}`);
  return pem;
}

export function registerCertImportCommand(cert: Command): void {
  cert
    .command("import <name>")
    .description("Import a certificate and private key from PEM files")
    .requiredOption(
      "--key <path>",
      "Private key PEM file (encrypted keys prompt for the passphrase)",
    )
    .requiredOption("--cert <path>", "Certificate PEM file (may contain the chain)")
    .option("--chain <path>", "Separate chain PEM file")
    .option("--project <project>", "Project scope")
    .option(
      "--auto-renew",
      "Auto ACME renewal (takes effect once the renewal daemon lands; until then use cert renew)",
    )
    .option("--renew-before-days <n>", "Renewal window in days", "30")
    .option("--json", "Output as JSON")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (name: string, options: CertImportOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        // `--key ""` must not fall through to the interactive hidden prompt:
        // resolveSecretValue treats an empty `fromFile` as "no file given", so
        // a scripted import with an unset path variable would silently stop
        // and wait for a human to type the key.
        if (options.key.trim() === "") {
          throw new Error("--key requires a path to a private key PEM file.");
        }
        if (options.cert.trim() === "") {
          throw new Error("--cert requires a path to a certificate PEM file.");
        }
        if (options.chain !== undefined && options.chain.trim() === "") {
          throw new Error("--chain requires a path to a chain PEM file, or omit it entirely.");
        }

        // Range-checked before the vault opens: an operator typo must not
        // reach a key file or a passphrase prompt (the `secret set` F4 lesson).
        const renewBeforeDays = parseIntOption(
          options.renewBeforeDays,
          "renew-before-days",
          MIN_RENEW_BEFORE_DAYS,
          MAX_RENEW_BEFORE_DAYS,
        );

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          // Creation is governed by token scope alone (`create` is not
          // grantable per secret), but the resolved caller still rides along as
          // attribution so the secret.create and cert.issue rows name the
          // principal — a token-bearing import must not look like the trusted
          // local path in the trail (V2 parity with `secret set`).
          const resolved = resolveTokenCaller(
            engine,
            { permission: "create", project: options.project, name },
            options.token ?? process.env.HARPOC_TOKEN,
          );

          const certificatePem = readPemFile(options.cert, "certificate");
          const chainPem =
            options.chain === undefined ? undefined : readPemFile(options.chain, "chain");

          const keyBuffer = await resolveSecretValue({ fromFile: options.key });
          try {
            const manager = new CertManager(engine);
            const { handle } = await manager.importCertificate(name, {
              privateKeyPem: keyBuffer.toString("utf8"),
              certificatePem,
              chainPem,
              project: options.project,
              autoRenew: options.autoRenew ?? false,
              renewBeforeDays,
              caller: resolved?.caller,
            });

            if (options.json) {
              printJson({ handle });
            } else {
              printRecord({ Handle: handle, Status: "imported" });
            }
          } finally {
            // Wiped on the failure path too: a refused import must not leave
            // the key sitting in a live buffer.
            wipeBuffer(keyBuffer);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
