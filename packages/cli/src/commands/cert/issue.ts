import type { Command } from "commander";
import { CertManager } from "@harpoc/cert-manager";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";
import { parseIntOption } from "../../utils/options.js";
import { promptHidden } from "../../utils/prompt.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import {
  assertAlgorithmPairing,
  parseAlgorithm,
  parseBits,
  parseCurve,
  DEFAULT_KEY_ALGORITHM,
} from "./key-algorithm-options.js";

const MIN_RENEW_BEFORE_DAYS = 1;
const MAX_RENEW_BEFORE_DAYS = 365;
const MIN_PORT = 1;
const MAX_PORT = 65535;

interface CertIssueOptions {
  domains: string;
  email: string;
  staging?: boolean;
  httpPort?: string;
  dns?: boolean;
  algorithm: string;
  bits?: string;
  curve?: string;
  autoRenew?: boolean;
  renewBeforeDays: string;
  project?: string;
  json?: boolean;
  token?: string;
}

/**
 * An empty entry is refused rather than dropped: `--domains example.com,` is an
 * operator typo, and silently issuing for a shorter list than was asked for is
 * exactly the kind of quiet divergence the `secret set` F4 lesson rules out.
 */
function parseDomains(value: string): string[] {
  const domains = value.split(",").map((domain) => domain.trim());
  if (domains.some((domain) => domain === "")) {
    throw new Error("--domains requires a comma-separated list of non-empty domain names.");
  }
  return domains;
}

/**
 * The dns-01 solver. The record goes to stderr so a `--json` run keeps stdout
 * machine-readable, and the wait uses the same single-line reader every other
 * CLI prompt uses: a closed or piped stdin settles it at EOF instead of
 * dangling, so a non-interactive run fails at the CA rather than hanging.
 */
async function publishDnsRecord(domain: string, txtValue: string): Promise<void> {
  console.error(`_acme-challenge.${domain} TXT ${txtValue}`);
  await promptHidden("Press Enter once the record is published and visible: ");
}

export function registerCertIssueCommand(cert: Command): void {
  cert
    .command("issue <name>")
    .description("Issue a certificate over ACME (Let's Encrypt) and store it in the vault")
    .requiredOption("--domains <list>", "Comma-separated domain names (the first is the CN)")
    .requiredOption("--email <email>", "Contact email for the ACME account")
    .option("--staging", "Use the Let's Encrypt staging directory")
    .option("--http-port <port>", "Port for the http-01 challenge responder (default: 80)")
    .option("--dns", "Solve dns-01 interactively instead of http-01")
    .option("--algorithm <rsa|ec>", "Certificate key algorithm", DEFAULT_KEY_ALGORITHM)
    .option("--bits <2048|4096>", "RSA key size (only with --algorithm rsa)")
    .option("--curve <P-256|P-384>", "EC named curve (only with --algorithm ec)")
    .option(
      "--auto-renew",
      "Renew automatically under `harpoc server start --cert-renew`, inside the renew-before window",
    )
    .option("--renew-before-days <n>", "Renewal window in days", "30")
    .option("--project <project>", "Project scope")
    .option("--json", "Output as JSON")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .action(async (name: string, options: CertIssueOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        // Everything below is range-checked before the vault opens (the
        // `secret set` F4 lesson, as in `cert import`/`cert csr`): an operator
        // typo must not cost a key-pair generation, an ACME account or a
        // rate-limited order.
        const domains = parseDomains(options.domains);
        if (options.email.trim() === "") {
          throw new Error("--email requires a contact email address for the ACME account.");
        }
        // dns-01 never starts the http-01 responder, so a port supplied
        // alongside --dns would be dead configuration. Refused rather than
        // silently dropped — the same rule `cert csr` applies to a --bits that
        // doesn't pair with the resolved algorithm.
        if (options.dns === true && options.httpPort !== undefined) {
          throw new Error(
            "--http-port only applies to the http-01 challenge; it has no effect with --dns.",
          );
        }
        // The manager range-checks the port too; parsing here only turns a
        // non-numeric argument into a message naming the option.
        const httpPort =
          options.httpPort === undefined
            ? undefined
            : parseIntOption(options.httpPort, "http-port", MIN_PORT, MAX_PORT);
        const renewBeforeDays = parseIntOption(
          options.renewBeforeDays,
          "renew-before-days",
          MIN_RENEW_BEFORE_DAYS,
          MAX_RENEW_BEFORE_DAYS,
        );
        const algorithm = parseAlgorithm(options.algorithm);
        const modulusLength = parseBits(options.bits);
        const namedCurve = parseCurve(options.curve);
        assertAlgorithmPairing(algorithm, modulusLength, namedCurve);

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          // Creation is governed by token scope alone (`create` is not
          // grantable per secret), but the resolved caller still rides along as
          // attribution so the secret.create and cert.issue rows name the
          // principal — the same V2 parity `cert import`/`cert csr` apply.
          const resolved = resolveTokenCaller(
            engine,
            { permission: "create", project: options.project, name },
            options.token ?? process.env.HARPOC_TOKEN,
          );

          const manager = new CertManager(engine);
          const issued = await manager.issueWithAcme(name, {
            domains,
            email: options.email,
            staging: options.staging ?? false,
            httpPort,
            dns01: options.dns === true ? publishDnsRecord : undefined,
            algorithm,
            modulusLength,
            namedCurve,
            project: options.project,
            autoRenew: options.autoRenew ?? false,
            renewBeforeDays,
            caller: resolved?.caller,
          });

          if (options.json) {
            printJson(issued);
          } else {
            printRecord({
              Handle: issued.handle,
              Subject: issued.status.subject,
              "Not after": formatTimestamp(issued.status.not_after),
              "Renewal status": issued.status.renewal_status,
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
