import type { Command } from "commander";
import type { InjectionPolicy, ResponseMode } from "@harpoc/shared";
import { injectionPolicyInputSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";

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
  acknowledgeInterpreter?: boolean;
  clear?: boolean;
  show?: boolean;
  json?: boolean;
}

const EMPTY_POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
};

/**
 * Merge the provided flag groups into the current policy. Groups the caller
 * omits keep their stored values — so e.g. `--url` alone cannot silently reset
 * a `status_only` response mode back to `filtered`. `--clear` starts from an
 * empty default policy instead of the stored one.
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
      "--acknowledge-interpreter",
      "Explicitly acknowledge allowlisting a known interpreter (sh, bash, python, node, ...) — collapses the capability ladder for this secret; refused and audited otherwise",
    )
    .option("--clear", "Reset the whole policy to defaults before applying the other flags")
    .option("--show", "Show the current policy instead of setting it")
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
            (options.clear ? 1 : 0);

          if (options.show || setCount === 0) {
            const policy = await engine.getInjectionPolicy(handle);
            printJson(policy);
            return;
          }

          const current = await engine.getInjectionPolicy(handle);
          const parsed = injectionPolicyInputSchema.safeParse(mergePolicy(current, options));
          if (!parsed.success) {
            throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
          }

          await engine.setInjectionPolicy(handle, parsed.data, {
            acknowledge_interpreters: options.acknowledgeInterpreter === true,
          });
          printSuccess(`Injection policy updated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
