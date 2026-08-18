import { OAuthGrantType, VaultError } from "@harpoc/shared";
import type { CallerContext, OAuthFlowResult, StartOAuthFlowInput } from "@harpoc/shared";
import { providerConfigFromFlowInput } from "./flow-input.js";
import type { OAuthManager } from "./oauth-manager.js";

/**
 * The completion signal names `has_access_token` deliberately: a provider that
 * issues no refresh token never reaches refresh_status "ok", while every
 * successful flow stores an access token.
 */
export const PENDING_AUTHORIZATION_MESSAGE =
  "Authorize in the browser at auth_url; the token is stored automatically when the callback arrives. Poll the OAuth token status until has_access_token is true.";

/**
 * The one grant-type dispatch behind REST `POST /oauth/authorize` and the
 * SDK's `startOAuthFlow`: wire input → provider config → manager call →
 * wire-safe {@link OAuthFlowResult}. Field-by-field projections are the
 * contract — neither the internal `secretId` nor a flow's `completion`
 * promise ever serializes (D2), and holding them here keeps the surfaces
 * from diverging copy by copy.
 */
export async function startOAuthFlowResult(
  manager: OAuthManager,
  input: StartOAuthFlowInput,
  caller?: CallerContext,
): Promise<OAuthFlowResult> {
  const { config, project } = providerConfigFromFlowInput(input);

  if (input.grant_type === OAuthGrantType.CLIENT_CREDENTIALS) {
    if (!config.client_secret) {
      throw VaultError.schemaValidation(
        "client_secret is required for the client_credentials grant",
      );
    }
    const result = await manager.startClientCredentials(input.name, config, project, caller);
    return { handle: result.handle, status: result.status, message: result.message };
  }

  if (input.grant_type === OAuthGrantType.DEVICE_CODE) {
    const device = await manager.startDeviceCode(input.name, config, project, caller);
    return {
      handle: device.handle,
      status: device.status,
      auth_url: device.auth_url,
      user_code: device.user_code,
      message: device.message,
    };
  }

  if (input.grant_type === OAuthGrantType.AUTHORIZATION_CODE) {
    const start = await manager.startAuthorizationCodeDeferred(input.name, config, project, caller);
    return {
      handle: start.handle,
      status: "pending_authorization",
      auth_url: start.authUrl,
      message: PENDING_AUTHORIZATION_MESSAGE,
    };
  }

  const unhandled: never = input.grant_type;
  throw new Error(`Unhandled grant_type: ${String(unhandled)}`);
}
