import { VaultError } from "@harpoc/shared";
import type { OAuthProviderConfig, OAuthProviderPreset } from "@harpoc/shared";

export interface ProviderPreset {
  auth_endpoint: string;
  token_endpoint: string;
  device_authorization_endpoint?: string;
  scopes_separator?: string;
  default_scopes?: string[];
}

export const PROVIDER_PRESETS: Record<string, ProviderPreset> = {
  github: {
    auth_endpoint: "https://github.com/login/oauth/authorize",
    token_endpoint: "https://github.com/login/oauth/access_token",
    device_authorization_endpoint: "https://github.com/login/device/code",
    default_scopes: ["repo", "user"],
  },
  google: {
    auth_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    default_scopes: ["openid", "email", "profile"],
  },
  microsoft: {
    auth_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    device_authorization_endpoint:
      "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
    default_scopes: ["openid", "email", "profile", "offline_access"],
  },
  slack: {
    auth_endpoint: "https://slack.com/oauth/v2/authorize",
    token_endpoint: "https://slack.com/api/oauth.v2.access",
    scopes_separator: ",",
    default_scopes: ["chat:write", "channels:read"],
  },
};

/**
 * Resolve a provider config by merging preset defaults with user overrides.
 * For "custom" provider, no preset is applied — all fields must be user-supplied.
 */
export function resolveProvider(config: OAuthProviderConfig): OAuthProviderConfig {
  if (config.provider === "custom") {
    return config;
  }

  const preset = PROVIDER_PRESETS[config.provider] as ProviderPreset | undefined;
  if (!preset) {
    throw VaultError.oauthProviderNotFound(config.provider);
  }

  return {
    ...config,
    auth_endpoint: config.auth_endpoint ?? preset.auth_endpoint,
    token_endpoint: config.token_endpoint ?? preset.token_endpoint,
    device_authorization_endpoint:
      config.device_authorization_endpoint ?? preset.device_authorization_endpoint,
    scopes: config.scopes ?? preset.default_scopes,
  };
}

/**
 * Get the scopes separator for a provider (defaults to space).
 */
export function getScopesSeparator(provider: OAuthProviderPreset): string {
  if (provider === "custom") return " ";
  const preset = PROVIDER_PRESETS[provider];
  return preset?.scopes_separator ?? " ";
}
