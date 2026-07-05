import type { Command } from "commander";
import { injectionPolicyInputSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

interface AllowOptions {
  command?: string[];
  url?: string[];
  env?: string[];
  show?: boolean;
  json?: boolean;
}

export function registerSecretAllowCommand(secret: Command): void {
  secret
    .command("allow <handle>")
    .description("Set or show a secret's injection allowlists (URL + command)")
    .option("--command <name>", "Allowlisted command for process execution (repeatable)", collect, [])
    .option("--url <pattern>", "Allowlisted URL pattern for HTTP injection (repeatable)", collect, [])
    .option("--env <name>", "Env var passed through to spawned processes (repeatable)", collect, [])
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
            (options.env?.length ?? 0);

          if (options.show || setCount === 0) {
            const policy = await engine.getInjectionPolicy(handle);
            printJson(policy);
            return;
          }

          const parsed = injectionPolicyInputSchema.safeParse({
            url_allowlist: options.url ?? [],
            command_allowlist: options.command ?? [],
            env_allowlist: options.env ?? [],
          });
          if (!parsed.success) {
            throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
          }

          await engine.setInjectionPolicy(handle, parsed.data);
          printSuccess(`Injection policy updated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
