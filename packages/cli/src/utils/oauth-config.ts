import { oauthProviderConfigSchema, startOAuthFlowInputSchema } from "@harpoc/shared";
import type { OAuthGrantType, OAuthProviderConfig } from "@harpoc/shared";
import { PROVIDER_PRESETS } from "@harpoc/oauth-proxy";

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

function formatIssues(issues: { path: (string | number)[]; message: string }[]): string {
  return issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
}

/**
 * Map `oauth connect` flags to a validated OAuthProviderConfig: input-schema
 * parse, preset endpoint merge (so the final parse's per-grant endpoint
 * requirements can be satisfied by presets), final config-schema parse.
 */
export function buildOAuthProviderConfig(
  name: string,
  grantType: OAuthGrantType,
  flags: OAuthConnectFlags,
  clientSecret: string | undefined,
): { config: OAuthProviderConfig; project?: string } {
  if (!flags.provider) {
    throw new Error("--provider is required (github | google | microsoft | slack | custom).");
  }
  if (!flags.clientId) {
    throw new Error("--client-id is required.");
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
    throw new Error(formatIssues(parsedInput.error.issues));
  }
  const input = parsedInput.data;

  const preset = input.provider === "custom" ? undefined : PROVIDER_PRESETS[input.provider];
  const tokenEndpoint = input.token_endpoint ?? preset?.token_endpoint;
  if (!tokenEndpoint) {
    throw new Error('--token-endpoint is required for provider "custom".');
  }

  const parsedConfig = oauthProviderConfigSchema.safeParse({
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
    redirect_uri: flags.redirectUri,
  });
  if (!parsedConfig.success) {
    throw new Error(formatIssues(parsedConfig.error.issues));
  }

  return { config: parsedConfig.data, project: input.project };
}
