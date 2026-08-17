import { VaultError, oauthProviderConfigSchema } from "@harpoc/shared";
import type { OAuthProviderConfig, StartOAuthFlowInput } from "@harpoc/shared";
import { PROVIDER_PRESETS } from "./providers.js";

function formatIssues(issues: { path: (string | number)[]; message: string }[]): string {
  return issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
}

/** Wire input → validated provider config: preset endpoint merge, then config-schema parse. */
export function providerConfigFromFlowInput(
  input: StartOAuthFlowInput,
  extras?: { redirect_uri?: string },
): { config: OAuthProviderConfig; project?: string } {
  const preset = input.provider === "custom" ? undefined : PROVIDER_PRESETS[input.provider];
  const tokenEndpoint = input.token_endpoint ?? preset?.token_endpoint;
  if (!tokenEndpoint) {
    throw VaultError.schemaValidation('token_endpoint is required for provider "custom"');
  }
  const parsed = oauthProviderConfigSchema.safeParse({
    provider: input.provider,
    grant_type: input.grant_type,
    token_endpoint: tokenEndpoint,
    auth_endpoint: input.auth_endpoint ?? preset?.auth_endpoint,
    device_authorization_endpoint:
      input.device_authorization_endpoint ?? preset?.device_authorization_endpoint,
    client_id: input.client_id,
    client_secret: input.client_secret,
    token_endpoint_auth_method: input.token_endpoint_auth_method,
    scopes: input.scopes,
    redirect_uri: extras?.redirect_uri,
  });
  if (!parsed.success) throw VaultError.schemaValidation(formatIssues(parsed.error.issues));
  return { config: parsed.data, project: input.project };
}
