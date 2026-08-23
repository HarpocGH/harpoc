import type { Command } from "commander";
import { IssuedTokenStatus } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { handleError, printJson, printTable, formatTimestamp } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";

/**
 * The issued-token registry (v1.4): claims metadata only. No listing can hand
 * back a JWT — the vault never stored one.
 */
export function registerAuthListCommand(auth: Command): void {
  auth
    .command("list")
    .description("List issued tokens (claims metadata only — never a token value)")
    .option("--agent <name>", "Only tokens issued to this agent")
    .option("--all", "Include expired and revoked tokens")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(
      async (
        options: { agent?: string; all?: boolean; token?: string; json?: boolean },
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

            const tokens = engine.listIssuedTokens(
              { agent: options.agent, status: options.all ? "all" : IssuedTokenStatus.ACTIVE },
              resolved?.caller,
            );

            if (options.json) {
              printJson(tokens);
            } else {
              printTable(
                tokens.map((t) => ({
                  JTI: t.jti,
                  Subject: t.subject,
                  Type: t.principal_type,
                  Agent: t.agent,
                  Scope: t.scope.join(","),
                  Label: t.label,
                  Issued: formatTimestamp(t.issued_at),
                  Expires: formatTimestamp(t.expires_at),
                  Status: t.status,
                })),
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
