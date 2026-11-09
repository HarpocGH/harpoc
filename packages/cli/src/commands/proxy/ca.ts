import { lstatSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Command } from "commander";
import { createCa, normalizeHost } from "@harpoc/cert-manager";
import { VaultError } from "@harpoc/shared";
import { loadUnlockedEngine, resolveVaultDir } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, printSuccess } from "../../utils/output.js";
import { parseIntOption } from "../../utils/options.js";
import {
  DEFAULT_CA_DAYS,
  DEFAULT_UNCONSTRAINED_CA_DAYS,
  MAX_CA_DAYS,
  MAX_UNCONSTRAINED_CA_DAYS,
  MIN_CA_DAYS,
} from "../../utils/option-bounds.js";
import { EXPORTED_CA_FILE_MODE, writeCaFile } from "../../utils/proxy-ca.js";

function collect(value: string, acc: string[]): string[] {
  return [...acc, value];
}

interface ProxyCaInitOptions {
  nameConstraints: string[];
  unconstrained?: boolean;
  days?: string;
  force?: boolean;
  json?: boolean;
}

export interface ProxyCaInitPlan {
  hosts: string[];
  unconstrained: boolean;
  days: number;
}

/**
 * `proxy ca init`'s options, every refusal before the vault opens (RD-B8-13, RX-B8-16): at least
 * one `--name-constraints` in both modes — the host list bounds the proxy's CONNECT set whether
 * or not the certificates carry the extension; each host through cert-manager's `normalizeHost`
 * (the issuer's own grammar, R-X7), its refusal prefixed with the flag and the value, duplicates
 * dropped after normalizing; `--days` decimal digits within the mode's cap, never clamped.
 */
export function parseProxyCaInitOptions(options: ProxyCaInitOptions): ProxyCaInitPlan {
  if (options.nameConstraints.length === 0) {
    throw VaultError.invalidInput(
      "proxy ca init needs --name-constraints <host> (repeatable): the hosts the proxy serves CONNECT for, with --unconstrained too",
    );
  }
  const unconstrained = options.unconstrained === true;
  const max = unconstrained ? MAX_UNCONSTRAINED_CA_DAYS : MAX_CA_DAYS;
  const days =
    options.days === undefined
      ? unconstrained
        ? DEFAULT_UNCONSTRAINED_CA_DAYS
        : DEFAULT_CA_DAYS
      : parseIntOption(options.days, "--days", MIN_CA_DAYS, max);
  const hosts = options.nameConstraints.map((entry) => {
    try {
      return normalizeHost(entry);
    } catch (err) {
      const reason = err instanceof VaultError ? err.message : "not a DNS name or an IP literal";
      throw VaultError.invalidInput(`--name-constraints ${JSON.stringify(entry)}: ${reason}`);
    }
  });
  return { hosts: [...new Set(hosts)], unconstrained, days };
}

/**
 * `proxy ca export --out`'s checks, before the vault opens: a value Commander took from the next
 * flag, an empty path, a missing directory and an existing entry that is not a regular file are
 * refused `INVALID_INPUT`; an existing regular file is replaced (the certificate is public — the
 * re-export after `init --force` is the documented step, and stdout redirection replaces a file
 * as well).
 */
export function assertExportOut(out: string): void {
  if (out.trim() === "") throw VaultError.invalidInput("--out: empty path");
  if (out.startsWith("-")) {
    throw VaultError.invalidInput(
      "--out: a flag, not a path (give a path that starts with a dash as ./-name)",
    );
  }
  const parent = dirname(resolve(out));
  let isDirectory = false;
  try {
    isDirectory = statSync(parent).isDirectory();
  } catch {
    // Refused below with the path, never the errno's text.
  }
  if (!isDirectory) throw VaultError.invalidInput(`--out: no such directory: ${parent}`);
  let entry: ReturnType<typeof lstatSync> | undefined;
  try {
    entry = lstatSync(out, { throwIfNoEntry: false });
  } catch {
    throw VaultError.invalidInput(`--out: cannot check ${out} (is its directory searchable?)`);
  }
  if (entry !== undefined && !entry.isFile()) {
    throw VaultError.invalidInput(`--out: ${out} exists and is not a regular file`);
  }
}

const iso = (ms: number): string => new Date(ms).toISOString();

export function registerProxyCaCommands(proxy: Command): void {
  const ca = proxy
    .command("ca")
    .description(
      "The Harpoc CA of the proxy's CONNECT mode (secret://harpoc-ca): created in the vault, its root exported for the consumers' trust",
    );

  ca.command("init")
    .description(
      "Create the Harpoc CA in the vault — a root and the intermediate it signs, name-constrained to the hosts the proxy serves CONNECT for (the root's key discarded) — and print the hosts, both expiries and both fingerprints; never a key",
    )
    .option(
      "--name-constraints <host>",
      "A host the proxy serves CONNECT for and the CA issues for: a DNS name (it and its subdomains) or an IP address (repeatable; required)",
      collect,
      [],
    )
    .option(
      "--unconstrained",
      `The fallback for a client that rejects a constrained root: certificates without name constraints (the proxy still serves the listed hosts alone), at most ${String(MAX_UNCONSTRAINED_CA_DAYS)} days`,
    )
    .option(
      "--days <n>",
      `The CA's lifetime in days (default ${String(DEFAULT_CA_DAYS)}, at most ${String(MAX_CA_DAYS)}; with --unconstrained default ${String(DEFAULT_UNCONSTRAINED_CA_DAYS)}, at most ${String(MAX_UNCONSTRAINED_CA_DAYS)})`,
    )
    .option("--force", "Replace an existing Harpoc CA (the old one is revoked)")
    .option("--json", "Output as JSON")
    .action(async (options: ProxyCaInitOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const plan = parseProxyCaInitOptions(options);
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const material = plan.unconstrained
            ? createCa({ permittedHosts: [], unconstrained: true, validityDays: plan.days })
            : createCa({ permittedHosts: plan.hosts, validityDays: plan.days });
          const created = await engine.createProxyCa({
            certPem: material.certPem,
            keyPem: material.keyPem,
            rootPem: material.rootPem,
            hosts: plan.hosts,
            unconstrained: plan.unconstrained,
            force: options.force === true,
          });
          if (options.json) {
            printJson({
              handle: created.handle,
              hosts: created.hosts,
              unconstrained: created.unconstrained,
              notAfter: created.notAfter,
              fingerprint256: created.fingerprint256,
              rootNotAfter: created.rootNotAfter,
              rootFingerprint256: created.rootFingerprint256,
              replaced: created.replaced,
            });
          } else {
            printRecord({
              Handle: created.handle,
              Hosts: created.hosts.join(", "),
              "Name constraints": created.unconstrained
                ? "none (unconstrained certificates)"
                : "the hosts, in both certificates",
              "Root not after": iso(created.rootNotAfter),
              "Root SHA-256": created.rootFingerprint256,
              "CA not after": iso(created.notAfter),
              "CA SHA-256": created.fingerprint256,
            });
            if (created.unconstrained) {
              console.error(
                `Warning: the Harpoc CA's certificates are unconstrained — a client trusting its root accepts a certificate for any host signed with its key, until ${iso(created.notAfter)}; the proxy itself serves CONNECT for the listed hosts alone.`,
              );
            }
            printSuccess(
              created.replaced
                ? "Harpoc CA replaced: the previous one is revoked. Restart server start --proxy (it rewrites <consumer>/ca.pem) and re-export the root for every consumer outside the runtime directory (harpoc proxy ca export)."
                : "Harpoc CA created. Restart server start --proxy to serve CONNECT with it: it writes the root as <consumer>/ca.pem into every consumer directory, and harpoc proxy ca export prints it for any other consumer.",
            );
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });

  ca.command("export")
    .description(
      "Print the Harpoc CA's root certificate (public — the trust anchor) to stdout, or write it to --out, for a consumer's trust (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO)",
    )
    .option(
      "--out <path>",
      "Write the root certificate to this file (mode 0644; a regular file there is replaced)",
    )
    .option("--json", "Output as JSON")
    .action(async (options: { out?: string; json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        if (options.out !== undefined) assertExportOut(options.out);
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const root = await engine.proxyCaCertificate();
          if (root === null) throw VaultError.proxyCaNotConfigured();
          if (options.out !== undefined) {
            writeCaFile(options.out, root.certPem, EXPORTED_CA_FILE_MODE);
            if (options.json) {
              printJson({
                handle: root.handle,
                out: options.out,
                notAfter: root.notAfter,
                fingerprint256: root.fingerprint256,
              });
            } else {
              printSuccess(
                `Harpoc CA root written to ${options.out} (SHA-256 ${root.fingerprint256}, until ${iso(root.notAfter)})`,
              );
            }
            return;
          }
          if (options.json) {
            printJson({
              handle: root.handle,
              certPem: root.certPem,
              notAfter: root.notAfter,
              fingerprint256: root.fingerprint256,
            });
          } else {
            process.stdout.write(root.certPem);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
