import type { Command } from "commander";
import type { ConnectionConfig, InjectionPolicy, ResponseMode } from "@harpoc/shared";
import { injectionPolicyInputSchema, renderSchemaIssues, VaultError } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { restModeOf, runRestMode } from "../../utils/rest-mode.js";

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
  /** Tri-state: true (--strict-tree-exit), false (--no-strict-tree-exit), undefined (keep stored). */
  strictTreeExit?: boolean;
  /** Tri-state: true (--proxy), false (--no-proxy), undefined (keep stored). */
  proxy?: boolean;
  /** Tri-state: true (--ssh-agent-socket), false (--no-ssh-agent-socket), undefined (keep stored). */
  sshAgentSocket?: boolean;
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
  strict_tree_exit: false,
  proxy: false,
  ssh_agent_socket: false,
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
    strict_tree_exit: options.strictTreeExit ?? base.strict_tree_exit,
    proxy: options.proxy ?? base.proxy,
    ssh_agent_socket: options.sshAgentSocket ?? base.ssh_agent_socket,
  };
}

/** The flag groups a call sets, `--clear` included: none (or `--show`) makes it a show. */
function countSetFlags(options: AllowOptions): number {
  return (
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
    (options.strictTreeExit !== undefined ? 1 : 0) +
    (options.proxy !== undefined ? 1 : 0) +
    (options.sshAgentSocket !== undefined ? 1 : 0) +
    (options.clear ? 1 : 0)
  );
}

/** The merged policy through the input schema; a refusal is `SCHEMA_VALIDATION_ERROR`. */
function parseMergedPolicy(current: InjectionPolicy, options: AllowOptions): InjectionPolicy {
  const parsed = injectionPolicyInputSchema.safeParse(mergePolicy(current, options));
  if (!parsed.success) {
    throw VaultError.schemaValidation(renderSchemaIssues(parsed.error));
  }
  return parsed.data;
}

/** The opt-in alone brokers nothing: the URL allowlist is deny-by-default. */
function noteProxyWithoutUrl(handle: string, options: AllowOptions, policy: InjectionPolicy): void {
  if (options.proxy === true && policy.url_allowlist.length === 0) {
    console.error(
      `Note: ${handle} is open to the egress proxy but allowlists no URL — the proxy brokers it to no origin until --url <pattern> adds one.`,
    );
  }
}

/**
 * The opt-in alone signs nothing: the agent socket signs for a host only when the secret pins its
 * host key (`secret connection --known-host`) and allowlists it (`--host`).
 */
function noteSshAgentSocketWithoutHost(
  handle: string,
  options: AllowOptions,
  policy: InjectionPolicy,
  connection: ConnectionConfig | undefined,
): void {
  if (options.sshAgentSocket !== true) return;
  if (policy.host_allowlist.length === 0) {
    console.error(
      `Note: ${handle} is open to the ssh-agent socket but allowlists no host — the socket signs with it for no host until --host <pattern> adds one.`,
    );
  }
  if ((connection?.ssh?.known_hosts.length ?? 0) === 0) {
    console.error(
      `Note: ${handle} is open to the ssh-agent socket but pins no host key — the socket signs with it for no host until secret connection ${handle} --known-host <line> pins one.`,
    );
  }
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
      "Require every child process spawned with this secret, stdio MCP downstream servers included, to run without network access (Linux: unshare user+net namespaces, or bwrap behind it; macOS: sandbox-exec deny-network; Windows: unsupported, uses are refused fail-closed)",
    )
    .option("--no-network-isolation", "Remove a stored network-isolation requirement")
    .option(
      "--fs-isolation",
      "Demand write-denying filesystem isolation for every process-mediated spawn and stdio MCP downstream (Linux: setpriv Landlock, util-linux >= 2.40, or bwrap's read-only root bind behind it; macOS: sandbox-exec; Windows: unsupported, uses are refused fail-closed)",
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
      "--strict-tree-exit",
      "Require that nothing a process-mediated child started outlives the call (process/git/ssh/sftp/docker and stdio MCP downstreams): Windows runs the child inside the vault's kill-on-close job in strict mode and refuses the use fail-closed where the wrapper is unavailable; POSIX kills the child's process group after it exits",
    )
    .option("--no-strict-tree-exit", "Remove a stored strict-tree-exit requirement")
    .option(
      "--proxy",
      "Allow the egress credential proxy (server start --proxy) to broker this secret: a request carrying its placeholder (harpoc:<name> or harpoc://<project>/<name>) is sent to an origin the --url allowlist admits, with the real value swapped in",
    )
    .option("--no-proxy", "Remove a stored egress-proxy opt-in")
    .option(
      "--ssh-agent-socket",
      "Allow the ssh-agent socket (server start --ssh-agent) to sign with this secret's SSH key for a consumer granted use, for a host that secret connection --known-host pins and the --host allowlist admits (session-bind@openssh.com)",
    )
    .option("--no-ssh-agent-socket", "Remove a stored ssh-agent-socket opt-in")
    .option(
      "--acknowledge-interpreter",
      "Explicitly acknowledge allowlisting a known interpreter (sh, bash, python, node, ...) or exec wrapper (sudo, xargs, find, tar, ...) — collapses the capability ladder for this secret; refused and audited otherwise",
    )
    .option("--clear", "Reset the whole policy to defaults before applying the other flags")
    .option("--show", "Show the current policy instead of setting it")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: AllowOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const rest = restModeOf(cmd);
        if (rest) {
          await runRestMode(rest, async (client) => {
            const setCount = countSetFlags(options);
            if (options.show || setCount === 0) {
              printJson(await client.getInjectionPolicy(handle));
              return;
            }
            const current = await client.getInjectionPolicy(handle);
            const connection =
              options.sshAgentSocket === true
                ? await client.getConnectionConfig(handle)
                : undefined;
            const merged = parseMergedPolicy(current, options);
            await client.setInjectionPolicy(handle, merged, {
              acknowledge_interpreters: options.acknowledgeInterpreter === true,
            });
            noteProxyWithoutUrl(handle, options, merged);
            noteSshAgentSocketWithoutHost(handle, options, merged, connection);
            printSuccess(`Injection policy updated (${handle})`);
          });
          return;
        }
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const setCount = countSetFlags(options);

          const tokenValue = options.token ?? process.env.HARPOC_TOKEN;

          if (options.show || setCount === 0) {
            const resolved = resolveTokenCallerForHandle(engine, "read", handle, tokenValue);
            const policy = await engine.getInjectionPolicy(handle, resolved?.caller);
            printJson(policy);
            return;
          }

          const resolved = resolveTokenCallerForHandle(engine, "admin", handle, tokenValue);
          // The merge read is attributed like the write it feeds: `admin`
          // satisfies the `read` gate this call runs, so nothing a caller
          // could not already reach is read and the row names the principal.
          const current = await engine.getInjectionPolicy(handle, resolved?.caller);
          // The pin the opt-in's note reads rides the same `read` gate and caller, before the
          // write: a refusal leaves the policy untouched.
          const connection =
            options.sshAgentSocket === true
              ? await engine.getConnectionConfig(handle, resolved?.caller)
              : undefined;
          const merged = parseMergedPolicy(current, options);

          await engine.setInjectionPolicy(
            handle,
            merged,
            { acknowledge_interpreters: options.acknowledgeInterpreter === true },
            resolved?.caller,
          );
          noteProxyWithoutUrl(handle, options, merged);
          noteSshAgentSocketWithoutHost(handle, options, merged, connection);
          printSuccess(`Injection policy updated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
