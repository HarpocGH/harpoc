// PKCE
export { generateCodeVerifier, generateCodeChallenge } from "./pkce.js";

// Providers
export { PROVIDER_PRESETS, resolveProvider, getScopesSeparator } from "./providers.js";
export type { ProviderPreset } from "./providers.js";

// Wire input mapping
export { formatIssues, providerConfigFromFlowInput } from "./flow-input.js";

// Wire flow dispatch (REST + SDK share it; MCP reuses the arms it can)
export { PENDING_AUTHORIZATION_MESSAGE, startOAuthFlowResult } from "./start-flow-result.js";

// Flows
export { AuthorizationCodeFlow } from "./flows/authorization-code.js";
export type { AuthCodeFlowStartResult, TokenExchangeResult } from "./flows/authorization-code.js";
export { ClientCredentialsFlow } from "./flows/client-credentials.js";
export type { ClientCredentialsResult } from "./flows/client-credentials.js";
export { DeviceCodeFlow } from "./flows/device-code.js";
export type { DeviceCodeStartResult, DeviceCodeTokenResult } from "./flows/device-code.js";

// Callback server
export { CallbackServer } from "./callback-server.js";
export type { CallbackResult } from "./callback-server.js";

// Token refresh
export { TokenRefreshScheduler } from "./token-refresh.js";
export type { TokenRefreshSchedulerOptions } from "./token-refresh.js";

// OAuth manager
export {
  OAuthManager,
  defaultOpenBrowser,
  DEFAULT_MAX_PENDING_AUTHORIZATIONS,
} from "./oauth-manager.js";
export type {
  OAuthManagerOptions,
  DeviceCodeFlowResult,
  AuthorizationCodeStart,
} from "./oauth-manager.js";
