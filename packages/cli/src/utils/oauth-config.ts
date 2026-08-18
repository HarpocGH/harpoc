import { VaultError, startOAuthFlowInputSchema } from "@harpoc/shared";
import type { OAuthGrantType, OAuthProviderConfig } from "@harpoc/shared";
import { formatIssues, providerConfigFromFlowInput } from "@harpoc/oauth-proxy";

export interface OAuthConnectFlags {
  provider?: string;
  clientId?: string;
  scopes?: string;
  authEndpoint?: string;
  tokenEndpoint?: string;
  deviceEndpoint?: string;
  redirectUri?: string;
  authMethod?: string;
  project?: string;
}

/**
 * Map `oauth connect` flags to a validated OAuthProviderConfig: flag-level
 * checks, input-schema parse, then the shared wire-input mapper (preset
 * endpoint merge + config-schema parse) all surfaces go through.
 */
export function buildOAuthProviderConfig(
  name: string,
  grantType: OAuthGrantType,
  flags: OAuthConnectFlags,
  clientSecret: string | undefined,
): { config: OAuthProviderConfig; project?: string } {
  if (!flags.provider) {
    throw VaultError.invalidInput(
      "--provider is required (github | google | microsoft | slack | custom).",
    );
  }
  if (!flags.clientId) {
    throw VaultError.invalidInput("--client-id is required.");
  }

  const scopes = flags.scopes
    ?.split(",")
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);

  const parsedInput = startOAuthFlowInputSchema.safeParse({
    name,
    provider: flags.provider,
    grant_type: grantType,
    client_id: flags.clientId,
    client_secret: clientSecret,
    token_endpoint_auth_method: flags.authMethod,
    scopes,
    project: flags.project,
    auth_endpoint: flags.authEndpoint,
    token_endpoint: flags.tokenEndpoint,
    device_authorization_endpoint: flags.deviceEndpoint,
  });
  if (!parsedInput.success) {
    throw VaultError.schemaValidation(formatIssues(parsedInput.error.issues));
  }

  return providerConfigFromFlowInput(parsedInput.data, { redirect_uri: flags.redirectUri });
}
