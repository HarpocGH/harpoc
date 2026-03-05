import type { Command } from "commander";
import type { InjectionConfig, SecretType } from "@harpoc/shared";
import { injectionConfigSchema, secretTypeSchema } from "@harpoc/shared";
import { resolveVaultDir, loadUnlockedEngine } from "../../utils/vault-loader.js";
import { promptSecret } from "../../utils/prompt.js";
import { handleError, printSuccess, printJson } from "../../utils/output.js";

export function registerSecretSetCommand(secret: Command): void {
  secret
    .command("set <name>")
    .description("Create or set a secret value")
    .option("-t, --type <type>", "Secret type (api_key, oauth_token, certificate)", "api_key")
    .option("-p, --project <project>", "Project scope")
    .option("--injection <type>", "Injection type (bearer, header, query, basic_auth)")
    .option("--header-name <name>", "Header name for header injection")
    .option("--query-param <name>", "Query parameter name for query injection")
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
          throw new Error(`Invalid secret type: "${typeStr}". Valid: api_key, oauth_token, certificate`);
        }
        const secretType = typeResult.data as SecretType;

        const injection = buildInjectionConfig(options);

        const engine = await loadUnlockedEngine(vaultDir);
        try {
          const result = await engine.createSecret({
            name,
            type: secretType,
            project: options.project,
            value: new TextEncoder().encode(value),
            injection,
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

function buildInjectionConfig(options: Record<string, string | undefined>): InjectionConfig | undefined {
  if (!options.injection) return undefined;
  const raw: Record<string, unknown> = { type: options.injection };
  if (options.headerName) raw.header_name = options.headerName;
  if (options.queryParam) raw.query_param = options.queryParam;
  const result = injectionConfigSchema.safeParse(raw);
  if (!result.success) {
    const msg = result.error.issues.map((i) => i.message).join(", ");
    throw new Error(`Invalid injection config: ${msg}`);
  }
  return result.data as InjectionConfig;
}
