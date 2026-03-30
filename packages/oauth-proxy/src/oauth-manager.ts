import type { VaultEngine } from "@harpoc/core";
import type { OAuthFlowResult, OAuthProviderConfig } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import { AuthorizationCodeFlow } from "./flows/authorization-code.js";
import { ClientCredentialsFlow } from "./flows/client-credentials.js";
import { DeviceCodeFlow } from "./flows/device-code.js";
import { CallbackServer } from "./callback-server.js";
import { resolveProvider } from "./providers.js";

export interface OAuthManagerOptions {
  openBrowser?: (url: string) => Promise<void>;
  callbackPort?: number;
  callbackTimeoutMs?: number;
}

export class OAuthManager {
  private engine: VaultEngine;
  private openBrowser: (url: string) => Promise<void>;
  private callbackPort: number;
  private callbackTimeoutMs: number;

  constructor(engine: VaultEngine, options?: OAuthManagerOptions) {
    this.engine = engine;
    this.openBrowser = options?.openBrowser ?? OAuthManager.defaultOpenBrowser;
    this.callbackPort = options?.callbackPort ?? 19876;
    this.callbackTimeoutMs = options?.callbackTimeoutMs ?? 5 * 60 * 1000;
  }

  /**
   * Start an authorization_code flow:
   * 1. Create OAuth secret in vault (PENDING)
   * 2. Start callback server (to get the bound port)
   * 3. Generate PKCE pair + state, construct auth URL
   * 4. Open browser to auth URL
   * 5. Wait for callback with auth code
   * 6. Exchange code for tokens
   * 7. Complete OAuth flow (secret → ACTIVE)
   */
  async startAuthorizationCode(
    name: string,
    config: OAuthProviderConfig,
    project?: string,
  ): Promise<OAuthFlowResult> {
    const resolved = resolveProvider(config);
    const { handle, secretId } = await this.engine.createOAuthSecret(name, resolved, project);

    const callbackServer = new CallbackServer(this.callbackPort);
    const flow = new AuthorizationCodeFlow();

    try {
      // Generate PKCE pair + state. We need the state for the callback server.
      // Use a temporary redirectUri — we'll adjust after the server is listening.
      const tempRedirectUri =
        resolved.redirect_uri ?? `http://localhost:${this.callbackPort}/oauth/callback`;
      const { state, code_verifier } = flow.startFlow(resolved, tempRedirectUri);

      // Start the callback server and wait until it's listening
      await callbackServer.start(state, this.callbackTimeoutMs);

      // Build the final redirect URI with the actual bound port
      const actualPort = callbackServer.listenPort;
      const redirectUri =
        resolved.redirect_uri ?? `http://localhost:${actualPort}/oauth/callback`;

      // Construct the auth URL manually using the SAME state and PKCE verifier
      const authUrl = new URL(resolved.auth_endpoint as string);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", resolved.client_id);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("state", state);
      const { generateCodeChallenge } = await import("./pkce.js");
      authUrl.searchParams.set("code_challenge", generateCodeChallenge(code_verifier));
      authUrl.searchParams.set("code_challenge_method", "S256");
      if (resolved.scopes && resolved.scopes.length > 0) {
        const { getScopesSeparator } = await import("./providers.js");
        authUrl.searchParams.set("scope", resolved.scopes.join(getScopesSeparator(resolved.provider)));
      }

      // Open the browser
      await this.openBrowser(authUrl.toString());

      // Wait for the callback
      const { code } = await callbackServer.waitForCallback();

      // Exchange code for tokens
      const tokens = await flow.handleCallback(
        code,
        resolved,
        redirectUri,
        code_verifier,
      );

      // Complete the flow in VaultEngine
      const expiresAt = tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined;
      await this.engine.completeOAuthFlow(
        secretId,
        tokens.access_token,
        tokens.refresh_token,
        expiresAt,
      );

      return {
        handle,
        status: "authorized",
        message: `OAuth flow completed successfully for ${resolved.provider}`,
      };
    } catch (err) {
      // If the flow fails, the secret remains in PENDING state.
      // The user can retry or delete it.
      throw err instanceof VaultError
        ? err
        : VaultError.oauthFlowFailed(err instanceof Error ? err.message : "Unknown error");
    } finally {
      await callbackServer.stop();
    }
  }

  /**
   * Start a client_credentials flow:
   * 1. Create OAuth secret in vault (PENDING)
   * 2. Exchange client_id + client_secret for access token
   * 3. Complete OAuth flow (secret → ACTIVE)
   */
  async startClientCredentials(
    name: string,
    config: OAuthProviderConfig,
    project?: string,
  ): Promise<OAuthFlowResult> {
    const resolved = resolveProvider(config);
    const { handle, secretId } = await this.engine.createOAuthSecret(name, resolved, project);

    try {
      const flow = new ClientCredentialsFlow();
      const tokens = await flow.authenticate(resolved);

      const expiresAt = tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined;
      await this.engine.completeOAuthFlow(secretId, tokens.access_token, undefined, expiresAt);

      return {
        handle,
        status: "authorized",
        message: `Client credentials flow completed for ${resolved.provider}`,
      };
    } catch (err) {
      throw err instanceof VaultError
        ? err
        : VaultError.oauthFlowFailed(err instanceof Error ? err.message : "Unknown error");
    }
  }

  /**
   * Start a device_code flow:
   * 1. Create OAuth secret in vault (PENDING)
   * 2. Request device code from provider
   * 3. Return user_code + verification_uri for display
   * 4. Start polling in the background
   */
  async startDeviceCode(
    name: string,
    config: OAuthProviderConfig,
    project?: string,
  ): Promise<OAuthFlowResult> {
    const resolved = resolveProvider(config);
    const { handle, secretId } = await this.engine.createOAuthSecret(name, resolved, project);

    const flow = new DeviceCodeFlow();
    const deviceResult = await flow.startFlow(resolved);

    // Start polling in the background (non-blocking)
    this.pollDeviceCodeInBackground(
      flow,
      deviceResult.device_code,
      deviceResult.interval,
      resolved,
      deviceResult.expires_in,
      secretId,
    );

    return {
      handle,
      status: "pending_authorization",
      auth_url: deviceResult.verification_uri,
      user_code: deviceResult.user_code,
      message: `Please visit ${deviceResult.verification_uri} and enter code: ${deviceResult.user_code}`,
    };
  }

  private pollDeviceCodeInBackground(
    flow: DeviceCodeFlow,
    deviceCode: string,
    interval: number,
    config: OAuthProviderConfig,
    expiresIn: number,
    secretId: string,
  ): void {
    flow
      .pollForToken(deviceCode, interval, config, expiresIn)
      .then(async (tokens) => {
        const expiresAt = tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined;
        await this.engine.completeOAuthFlow(
          secretId,
          tokens.access_token,
          tokens.refresh_token,
          expiresAt,
        );
      })
      .catch(() => {
        // Device code flow failed or timed out.
        // Secret remains in PENDING state.
      });
  }

  private static async defaultOpenBrowser(url: string): Promise<void> {
    const openModule = await import("open");
    await openModule.default(url);
  }
}
