import type { Command } from "commander";
import type { SecretType } from "@harpoc/shared";
import { secretTypeSchema, VaultError } from "@harpoc/shared";
import { wipeBuffer } from "@harpoc/core";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { resolveSecretValue } from "../../utils/secret-value.js";
import { handleError, printSuccess, printJson } from "../../utils/output.js";
import { resolveTokenCaller, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { restModeOf, runRestMode } from "../../utils/rest-mode.js";

interface SecretSetOptions {
  type?: string;
  project?: string;
  fromFile?: string;
  decrypt?: boolean;
  token?: string;
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
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action(async (name: string, options: SecretSetOptions, cmd: Command) => {
      const vaultDir = resolveVaultDir(cmd.optsWithGlobals().vaultDir);
      const json = "json" in options;
      try {
        const typeStr = options.type ?? "api_key";
        const typeResult = secretTypeSchema.safeParse(typeStr);
        if (!typeResult.success) {
          throw VaultError.invalidInput(
            `Invalid secret type: "${typeStr}". Valid: api_key, oauth_token, certificate`,
          );
        }
        const secretType = typeResult.data as SecretType;

        // The value is read here and sent base64 in the create body: the operator typing it
        // runs this CLI, and the server never echoes it back.
        const rest = restModeOf(cmd);
        if (rest) {
          await runRestMode(rest, async (client) => {
            const value = await resolveSecretValue({
              fromFile: options.fromFile,
              noDecrypt: options.decrypt === false,
            });
            try {
              const result = await client.createSecret({
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
            }
          });
          return;
        }

        // Engine first: a sealed vault must fail before the user types a
        // value or key passphrase, and the resolved plaintext must never
        // exist outside a wiping finally.
        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const resolved = resolveTokenCaller(
            engine,
            { permission: "create", project: options.project, name },
            options.token ?? process.env.HARPOC_TOKEN,
          );
          const value = await resolveSecretValue({
            fromFile: options.fromFile,
            noDecrypt: options.decrypt === false,
          });
          try {
            const result = await engine.createSecret(
              {
                name,
                type: secretType,
                project: options.project,
                value,
              },
              resolved?.caller,
            );

            if (json) {
              printJson(result);
            } else {
              printSuccess(`Secret '${name}' created (${result.handle})`);
            }
          } finally {
            wipeBuffer(value);
          }
        } finally {
          await engine.destroy();
        }
      } catch (err) {
        handleError(err, json);
      }
    });
}
