import type { Command } from "commander";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { promptConfirm } from "../../utils/prompt.js";
import { handleError, printSuccess, printJson } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

export function registerAgentDeleteCommand(agent: Command): void {
  agent
    .command("delete <name>")
    .description("Delete an agent, revoking its tokens and removing its grants")
    .option("--confirm", "Skip confirmation prompt")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(
      async (
        name: string,
        options: { confirm?: boolean; token?: string; json?: boolean },
        cmd: Command,
      ) => {
        const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
        try {
          // Engine first (the secret/delete.ts precedent): a sealed vault, a
          // scope refusal and an unknown agent all precede the prompt.
          const engine = await loadUnlockedEngine(vaultDir);
          try {
            const resolved = resolveTokenCaller(
              engine,
              { permission: "admin" },
              options.token ?? process.env.HARPOC_TOKEN,
            );

            const current = engine.getAgent(name, resolved?.caller);
            if (!options.confirm) {
              const yes = await promptConfirm(
                `Delete agent ${name}? This revokes ${String(current.active_tokens)} live token(s) and removes ${String(current.grants)} grant(s).`,
              );
              if (!yes) {
                console.error("Aborted.");
                return;
              }
            }

            const result = engine.deleteAgent(name, resolved?.caller);

            if (options.json) {
              printJson(result);
            } else {
              printSuccess(
                `Agent deleted (${name}); ${String(result.revoked_tokens)} token(s) revoked, ${String(result.removed_grants)} grant(s) removed`,
              );
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
