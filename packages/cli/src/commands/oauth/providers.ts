import type { Command } from "commander";
import { PROVIDER_PRESETS } from "@harpoc/oauth-proxy";
import { printJson, printRecord } from "../../utils/output.js";

export function registerOAuthProvidersCommand(parent: Command): void {
  parent
    .command("providers")
    .description("List OAuth provider presets and their endpoints")
    .option("--json", "Output JSON")
    .action((options: { json?: boolean }) => {
      const providers = Object.entries(PROVIDER_PRESETS).map(([provider, preset]) => ({
        provider,
        auth_endpoint: preset.auth_endpoint,
        token_endpoint: preset.token_endpoint,
        device_authorization_endpoint: preset.device_authorization_endpoint ?? null,
        default_scopes: preset.default_scopes ?? [],
        scopes_separator: preset.scopes_separator ?? " ",
        token_endpoint_auth_method: preset.token_endpoint_auth_method ?? null,
      }));
      if (options.json) {
        printJson({ providers });
        return;
      }
      for (const p of providers) {
        console.log(p.provider);
        printRecord({
          auth: p.auth_endpoint,
          token: p.token_endpoint,
          device: p.device_authorization_endpoint,
          scopes: p.default_scopes.length > 0 ? p.default_scopes.join(", ") : undefined,
        });
      }
      console.log(
        '\nProvider "custom" is also accepted — supply endpoints via --auth-endpoint / --token-endpoint / --device-endpoint.',
      );
    });
}
