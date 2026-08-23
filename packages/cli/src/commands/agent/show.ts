import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printRecord, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerAgentShowCommand(agent: Command): void {
  agent
    .command("show <name>")
    .description("Show one registered agent")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (name: string, options: { token?: string; json?: boolean }, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCaller(
            engine,
            { permission: "admin" },
            options.token ?? process.env.HARPOC_TOKEN,
          );

          const found = engine.getAgent(name, resolved?.caller);

          if (options.json) {
            printJson(found);
          } else {
            printRecord({
              ID: found.id,
              Name: found.name,
              Description: found.description,
              Owner: found.owner,
              Status: found.status,
              Created: formatTimestamp(found.created_at),
              Updated: formatTimestamp(found.updated_at),
              Deactivated: formatTimestamp(found.deactivated_at),
              "Last active": formatTimestamp(found.last_active_at),
              "Active tokens": found.active_tokens,
              Grants: found.grants,
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
