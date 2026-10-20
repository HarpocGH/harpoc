import { OAuthProviderPreset } from "./types.js";

/**
 * The separator between the scopes of one `scope` parameter: RFC 6749 §3.3's
 * space, except for a preset that documents its own. The one table both
 * token-endpoint callers join through — oauth-proxy's flows and core's
 * client-credentials re-exchange — so a re-exchange sends the scope string
 * the first exchange sent.
 */
export function oauthScopesSeparator(provider: OAuthProviderPreset): string {
  return provider === OAuthProviderPreset.SLACK ? "," : " ";
}
