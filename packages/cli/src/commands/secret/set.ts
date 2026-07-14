import type { Command } from "commander";
import type { SecretType } from "@harpoc/shared";
import { secretTypeSchema } from "@harpoc/shared";
import { wipeBuffer } from "@harpoc/core";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { resolveSecretValue } from "../../utils/secret-value.js";
import { handleError, printSuccess, printJson } from "../../utils/output.js";

interface SecretSetOptions {
  type?: string;
  project?: string;
  fromFile?: string;
  decrypt?: boolean;
  json?: boolean;
}

export function registerSecretSetCommand(secret: Command): void {
  secret
    .command("set <name>")
    .description("Create or set a secret value")
    .option("-t, --type <type>", "Secret type (api_key, oauth_token, certificate)", "api_key")
    .option("-p, --project <project>", "Project scope")
    .option("--from-file <path>", "Read the secret value from a file instead of prompting")
    .option(
      "--no-decrypt",
      "Store encrypted private-key material verbatim instead of decrypting at import",
    )
    .option("--json", "Output as JSON")
    .action(async (name: string, options: SecretSetOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      const json = "json" in options;
      try {
        const value = await resolveSecretValue({
          fromFile: options.fromFile,
          noDecrypt: options.decrypt === false,
        });

        const typeStr = options.type ?? "api_key";
        const typeResult = secretTypeSchema.safeParse(typeStr);
        if (!typeResult.success) {
          wipeBuffer(value);
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
            value,
          });

          if (json) {
            printJson(result);
          } else {
            printSuccess(`Secret '${name}' created (${result.handle})`);
          }
        } finally {
          wipeBuffer(value);
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, json);
      }
    });
}
