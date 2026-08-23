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

interface UpdateOptions {
  description?: string;
  owner?: string;
  clearDescription?: boolean;
  clearOwner?: boolean;
  token?: string;
  json?: boolean;
}

export function registerAgentUpdateCommand(agent: Command): void {
  agent
    .command("update <name>")
    .description("Update an agent's description or owner")
    .option("--description <text>", "Human-readable description")
    .option("--owner <text>", "Owning team or person")
    .option("--clear-description", "Remove the stored description")
    .option("--clear-owner", "Remove the stored owner")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (name: string, options: UpdateOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      try {
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCaller(
            engine,
            { permission: "admin" },
            options.token ?? process.env.HARPOC_TOKEN,
          );

          // Refused, not dropped: a set flag and its clear twin contradict, and
          // silently letting one win would write the operator's other intent away.
          if (options.description !== undefined && options.clearDescription) {
            throw new Error("--description and --clear-description are mutually exclusive");
          }
          if (options.owner !== undefined && options.clearOwner) {
            throw new Error("--owner and --clear-owner are mutually exclusive");
          }

          if (
            options.description === undefined &&
            options.owner === undefined &&
            !options.clearDescription &&
            !options.clearOwner
          ) {
            throw new Error(
              "Nothing to update. Pass --description, --owner, --clear-description or --clear-owner.",
            );
          }

          // The engine replaces both fields; an omitted flag here means "keep",
          // so the stored value is read first and sent back unchanged.
          const current = engine.getAgent(name, resolved?.caller);
          const updated = engine.updateAgent(
            name,
            {
              description: options.clearDescription
                ? undefined
                : (options.description ?? current.description ?? undefined),
              owner: options.clearOwner ? undefined : (options.owner ?? current.owner ?? undefined),
            },
            resolved?.caller,
          );

          if (options.json) {
            printJson(updated);
          } else {
            printRecord({
              Name: updated.name,
              Status: updated.status,
              Owner: updated.owner,
              Description: updated.description,
              Updated: formatTimestamp(updated.updated_at),
            });
            printSuccess("Agent updated.");
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
