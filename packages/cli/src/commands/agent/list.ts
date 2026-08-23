import type { Command } from "commander";
import { AgentStatus } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printTable, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerAgentListCommand(agent: Command): void {
  agent
    .command("list")
    .description("List registered agents")
    .option("--all", "Include deactivated agents")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (options: { all?: boolean; token?: string; json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCaller(
            engine,
            { permission: "admin" },
            options.token ?? process.env.HARPOC_TOKEN,
          );

          const agents = engine.listAgents(
            options.all ? "all" : AgentStatus.ACTIVE,
            resolved?.caller,
          );

          if (options.json) {
            printJson(agents);
          } else {
            printTable(
              agents.map((a) => ({
                Name: a.name,
                Status: a.status,
                Owner: a.owner,
                "Last active": formatTimestamp(a.last_active_at),
                Tokens: a.active_tokens,
                Grants: a.grants,
              })),
            );
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
