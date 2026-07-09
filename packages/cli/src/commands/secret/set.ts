import type { Command } from "commander";
import type { SecretType } from "@harpoc/shared";
import { secretTypeSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { promptSecret } from "../../utils/prompt.js";
import { handleError, printSuccess, printJson } from "../../utils/output.js";

export function registerSecretSetCommand(secret: Command): void {
  secret
    .command("set <name>")
    .description("Create or set a secret value")
    .option("-t, --type <type>", "Secret type (api_key, oauth_token, certificate)", "api_key")
    .option("-p, --project <project>", "Project scope")
    .option("--json", "Output as JSON")
    .action(async (name: string, options: Record<string, string | undefined>, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      const json = "json" in options;
      try {
        const value = await promptSecret();
        if (!value) {
          console.error("Error: Secret value cannot be empty.");
          process.exit(1);
        }

        const typeStr = options.type ?? "api_key";
        const typeResult = secretTypeSchema.safeParse(typeStr);
        if (!typeResult.success) {
          throw new Error(
            `Invalid secret type: "${typeStr}". Valid: api_key, oauth_token, certificate`,
          );
        }
        const secretType = typeResult.data as SecretType;

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const result = await engine.createSecret({
            name,
            type: secretType,
            project: options.project,
            value: new TextEncoder().encode(value),
          });

          if (json) {
            printJson(result);
          } else {
            printSuccess(`Secret '${name}' created (${result.handle})`);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, json);
      }
    });
}
