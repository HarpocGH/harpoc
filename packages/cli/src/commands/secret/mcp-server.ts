import type { Command } from "commander";
import { mcpServerConfigSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

interface McpServerOptions {
  name?: string;
  transport?: string;
  command?: string;
  arg?: string[];
  envVar?: string;
  cwd?: string;
  url?: string;
  show?: boolean;
  delete?: boolean;
  json?: boolean;
}

export function registerSecretMcpServerCommand(secret: Command): void {
  secret
    .command("mcp-server <handle>")
    .description(
      "Configure the downstream MCP server this secret authenticates (trusted admin path)",
    )
    .option("--name <name>", "Server name referenced by use_secret's action.server")
    .option("--transport <type>", "Transport: stdio | http")
    .option("--command <command>", "Launch command (stdio transport)")
    .option("--arg <arg>", "Launch argument (repeatable, stdio transport)", collect, [])
    .option("--env-var <name>", "Env var to inject the secret into (stdio transport)")
    .option("--cwd <dir>", "Working directory (stdio transport)")
    .option("--url <url>", "Downstream Streamable HTTP endpoint (http transport)")
    .option("--show", "Show the current config instead of setting it")
    .option("--delete", "Remove the config")
    .option("--json", "Output as JSON")
    .action(async (handle: string, options: McpServerOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          if (options.delete) {
            const deleted = await engine.deleteMcpServerConfig(handle);
            printSuccess(
              deleted
                ? `MCP server config removed (${handle})`
                : `No MCP server config set (${handle})`,
            );
            return;
          }

          if (options.show || (!options.name && !options.transport)) {
            const config = await engine.getMcpServerConfig(handle);
            printJson(config ?? null);
            return;
          }

          const parsed = mcpServerConfigSchema.safeParse({
            server_name: options.name,
            transport: options.transport,
            command: options.command,
            args: options.arg && options.arg.length > 0 ? options.arg : undefined,
            env_var: options.envVar,
            working_directory: options.cwd,
            url: options.url,
          });
          if (!parsed.success) {
            throw new Error(parsed.error.issues.map((i) => i.message).join(", "));
          }

          await engine.setMcpServerConfig(handle, parsed.data);
          printSuccess(`MCP server config updated (${handle})`);
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
