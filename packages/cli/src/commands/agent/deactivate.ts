import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printSuccess, printJson } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerAgentDeactivateCommand(agent: Command): void {
  agent
    .command("deactivate <name>")
    .description("Deactivate an agent and revoke every token it still holds")
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

          const result = engine.deactivateAgent(name, resolved?.caller);

          if (options.json) {
            printJson(result);
          } else {
            printSuccess(
              `Agent deactivated (${name}); ${String(result.revoked_tokens)} token(s) revoked`,
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
