import type { Command } from "commander";
import { CertManager } from "@harpoc/cert-manager";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import {
  assertAlgorithmPairing,
  parseAlgorithm,
  parseBits,
  parseCurve,
} from "./key-algorithm-options.js";

interface CertCsrOptions {
  subject: string;
  sans?: string;
  algorithm: string;
  bits?: string;
  curve?: string;
  project?: string;
  json?: boolean;
  token?: string;
}

function parseSans(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  return value.split(",").map((s) => s.trim());
}

export function registerCertCsrCommand(cert: Command): void {
  cert
    .command("csr <name>")
    .description("Generate a private key and a PKCS#10 certificate signing request")
    .requiredOption("--subject <cn>", "Common name for the certificate (a bare CN, not a DN)")
    .option("--sans <list>", "Comma-separated subject alternative names (DNS names or IPs)")
    .option("--algorithm <rsa|ec>", "Key algorithm", "ec")
    .option("--bits <2048|4096>", "RSA key size (only with --algorithm rsa)")
    .option("--curve <P-256|P-384>", "EC named curve (only with --algorithm ec)")
    .option("--project <project>", "Project scope")
    .option("--json", "Output as JSON")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (name: string, options: CertCsrOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        // Parsed before the vault opens (the `secret set` F4 lesson): an
        // operator typo must not spend a key-pair generation or reach the
        // engine.
        const algorithm = parseAlgorithm(options.algorithm);
        const modulusLength = parseBits(options.bits);
        const namedCurve = parseCurve(options.curve);
        assertAlgorithmPairing(algorithm, modulusLength, namedCurve);
        const sans = parseSans(options.sans);

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          // Creation is governed by token scope alone (`create` is not
          // grantable per secret), but the resolved caller still rides along
          // as attribution so the secret.create row names the principal — the
          // same V2 parity `cert import` applies.
          const resolved = resolveTokenCaller(
            engine,
            { permission: "create", project: options.project, name },
            options.token ?? process.env.HARPOC_TOKEN,
          );

          const manager = new CertManager(engine);
          const { handle, csrPem } = await manager.generateCsr(name, {
            commonName: options.subject,
            sans,
            algorithm,
            modulusLength,
            namedCurve,
            project: options.project,
            caller: resolved?.caller,
          });

          if (options.json) {
            printJson({ handle, csrPem });
          } else {
            // The CSR PEM is the command's payload — it goes to stdout
            // verbatim (no added newline: the PEM already ends in one) so it
            // can be piped straight into another tool. Everything else is
            // guidance and belongs on stderr.
            process.stdout.write(csrPem);
            printSuccess(`CSR generated: ${handle} (PENDING — awaiting the issued certificate)`);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
