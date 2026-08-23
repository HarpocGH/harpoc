import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import {
  handleError,
  printSuccess,
  printJson,
  printRecord,
  formatTimestamp,
} from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerAgentRegisterCommand(agent: Command): void {
  agent
    .command("register <name>")
    .description("Register an agent identity")
    .option("--description <text>", "Human-readable description")
    .option("--owner <text>", "Owning team or person")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(
      async (
        name: string,
        options: { description?: string; owner?: string; token?: string; json?: boolean },
        cmd: Command,
      ) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const resolved = resolveTokenCaller(
              engine,
              { permission: "admin" },
              options.token ?? process.env.HARPOC_TOKEN,
            );

            const registered = engine.registerAgent(
              { name, description: options.description, owner: options.owner },
              resolved?.caller,
            );

            if (options.json) {
              printJson(registered);
            } else {
              printRecord({
                Name: registered.name,
                Status: registered.status,
                Owner: registered.owner,
                Description: registered.description,
                Created: formatTimestamp(registered.created_at),
              });
              printSuccess("Agent registered.");
            }
          } finally {
            await engine.destroy();
          }
        } catch (err) {
          handleError(err, options.json);
        }
      },
    );
}
