import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printSuccess, printJson } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerAgentActivateCommand(agent: Command): void {
  agent
    .command("activate <name>")
    .description("Reactivate a deactivated agent (revoked tokens stay revoked)")
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

          const activated = engine.activateAgent(name, resolved?.caller);

          if (options.json) {
            printJson(activated);
          } else {
            printSuccess(`Agent activated (${activated.name})`);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
