import type { Command } from "commander";
import type { InjectionPolicy, ResponseMode } from "@harpoc/shared";
import { injectionPolicyInputSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

export interface AllowOptions {
  command?: string[];
  url?: string[];
  env?: string[];
  host?: string[];
  responseMode?: string;
  responseHeader?: string[];
  /** Tri-state: true (--network-isolation), false (--no-network-isolation), undefined (keep stored). */
  networkIsolation?: boolean;
  /** Tri-state: true (--fs-isolation), false (--no-fs-isolation), undefined (keep stored). */
  fsIsolation?: boolean;
  /** Additive: provided patterns are added to the stored allowlist, not replaced. */
  recipient?: string[];
  /** Tri-state: true (--imap-read-only), false (--no-imap-read-only), undefined (keep stored). */
  imapReadOnly?: boolean;
  acknowledgeInterpreter?: boolean;
  clear?: boolean;
  show?: boolean;
  token?: string;
  json?: boolean;
}

const EMPTY_POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
};

/**
 * Merge the provided flag groups into the current policy. Groups the caller
 * omits keep their stored values — so e.g. `--url` alone cannot silently reset
 * a `status_only` response mode back to `filtered`, or drop a stored
 * `network_isolation` or `fs_isolation` requirement. `--clear` starts from an
 * empty default policy instead of the stored one.
 *
 * `--recipient` is deliberately additive (unlike every other allowlist flag
 * here, which replaces wholesale): recipients are typically granted one at a
 * time, so a `--recipient` update merges with the stored list rather than
 * requiring the caller to restate every existing entry. `--clear` still
 * empties the list first, same as the other groups.
 */
export function mergePolicy(current: InjectionPolicy, options: AllowOptions): InjectionPolicy {
  const base = options.clear ? EMPTY_POLICY : current;
  return {
    url_allowlist: options.url?.length ? options.url : base.url_allowlist,
    command_allowlist: options.command?.length ? options.command : base.command_allowlist,
    env_allowlist: options.env?.length ? options.env : base.env_allowlist,
    host_allowlist: options.host?.length ? options.host : base.host_allowlist,
    response_mode: (options.responseMode as ResponseMode | undefined) ?? base.response_mode,
    response_header_allowlist: options.responseHeader?.length
      ? options.responseHeader
      : base.response_header_allowlist,
    network_isolation: options.networkIsolation ?? base.network_isolation,
    fs_isolation: options.fsIsolation ?? base.fs_isolation,
    smtp_recipient_allowlist: options.recipient?.length
      ? Array.from(new Set([...base.smtp_recipient_allowlist, ...options.recipient]))
      : base.smtp_recipient_allowlist,
    imap_read_only: options.imapReadOnly ?? base.imap_read_only,
  };
}

export function registerSecretAllowCommand(secret: Command): void {
  secret
    .command("allow <handle>")
    .description(
      "Set or show a secret's injection policy (URL/host/command allowlists, HTTP response mode); omitted flags keep their stored values",
    )
    .option(
      "--command <name>",
      "Allowlisted command for process execution (repeatable)",
      collect,
      [],
    )
    .option(
      "--url <pattern>",
      "Allowlisted URL pattern for HTTP injection (repeatable)",
      collect,
      [],
    )
    .option(
      "--host <pattern>",
      "Allowlisted host or host:port for database/SSH/Git-SSH (repeatable)",
      collect,
      [],
    )
    .option("--env <name>", "Env var passed through to spawned processes (repeatable)", collect, [])
    .option(
      "--response-mode <mode>",
      "HTTP response mode: full | filtered | status_only (default filtered)",
    )
    .option(
      "--response-header <name>",
      "Header still returned under status_only (repeatable)",
      collect,
      [],
    )
    .option(
      "--network-isolation",
      "Require every child process spawned with this secret to run without network access (Linux: unshare user+net namespaces; macOS: sandbox-exec deny-network; Windows: unsupported — uses are refused fail-closed)",
    )
    .option("--no-network-isolation", "Remove a stored network-isolation requirement")
    .option(
      "--fs-isolation",
      "demand write-denying filesystem isolation for every process-mediated spawn (Linux: setpriv Landlock, util-linux >= 2.40; macOS: sandbox-exec; Windows: unsupported — uses are refused fail-closed)",
    )
    .option("--no-fs-isolation", "Remove a stored filesystem-isolation requirement")
    .option(
      "--recipient <pattern>",
      "Allowlisted SMTP recipient pattern to add (repeatable, additive — merges with the stored list)",
      collect,
      [],
    )
    .option(
      "--imap-read-only",
      "Refuse mutating IMAP operations (store/move/copy/expunge) for this secret",
    )
    .option("--no-imap-read-only", "Remove a stored IMAP read-only requirement")
    .option(
      "--acknowledge-interpreter",
      "Explicitly acknowledge allowlisting a known interpreter (sh, bash, python, node, ...) — collapses the capability ladder for this secret; refused and audited otherwise",
    )
    .option("--clear", "Reset the whole policy to defaults before applying the other flags")
    .option("--show", "Show the current policy instead of setting it")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: AllowOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const setCount =
            (options.command?.length ?? 0) +
            (options.url?.length ?? 0) +
            (options.host?.length ?? 0) +
            (options.env?.length ?? 0) +
            (options.responseHeader?.length ?? 0) +
            (options.responseMode !== undefined ? 1 : 0) +
            (options.networkIsolation !== undefined ? 1 : 0) +
            (options.fsIsolation !== undefined ? 1 : 0) +
            (options.recipient?.length ?? 0) +
            (options.imapReadOnly !== undefined ? 1 : 0) +
            (options.clear ? 1 : 0);

          const tokenValue = options.token ?? process.env.HARPOC_TOKEN;

          if (options.show || setCount === 0) {
            const resolved = resolveTokenCallerForHandle(engine, "read", handle, tokenValue);
            const policy = await engine.getInjectionPolicy(handle, resolved?.caller);
            printJson(policy);
            return;
          }

          const resolved = resolveTokenCallerForHandle(engine, "admin", handle, tokenValue);
          // The merge read is the command's own mechanics, deliberately
          // caller-less (its result never reaches the caller); the caller's
          // gate is the admin check inside setInjectionPolicy (R1: the
          // injection policy is the widening half of a secret's configuration)
          // — the REST membership-check precedent.
          const current = await engine.getInjectionPolicy(handle);
          const parsed = injectionPolicyInputSchema.safeParse(mergePolicy(current, options));
          if (!parsed.success) {
            throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
          }

          await engine.setInjectionPolicy(
            handle,
            parsed.data,
            { acknowledge_interpreters: options.acknowledgeInterpreter === true },
            resolved?.caller,
          );
          printSuccess(`Injection policy updated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
