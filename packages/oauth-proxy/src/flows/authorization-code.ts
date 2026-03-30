import { randomBytes } from "node:crypto";
import { VaultError } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { generateCodeChallenge, generateCodeVerifier } from "../pkce.js";
import { getScopesSeparator } from "../providers.js";

export interface AuthCodeFlowStartResult {
  auth_url: string;
  state: string;
  code_verifier: string;
}

export interface TokenExchangeResult {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

export class AuthorizationCodeFlow {
  /**
   * Build the authorization URL with PKCE and state parameters.
   * Returns the URL to open in a browser, plus the state and verifier to keep in memory.
   */
  startFlow(config: OAuthProviderConfig, redirectUri: string): AuthCodeFlowStartResult {
    if (!config.auth_endpoint) {
      throw VaultError.oauthFlowFailed("auth_endpoint is required for authorization_code flow");
    }

    const state = randomBytes(32).toString("hex");
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const url = new URL(config.auth_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.client_id);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    if (config.scopes && config.scopes.length > 0) {
      const separator = getScopesSeparator(config.provider);
      url.searchParams.set("scope", config.scopes.join(separator));
    }

    return {
      auth_url: url.toString(),
      state,
      code_verifier: codeVerifier,
    };
  }

  /**
   * Exchange the authorization code for tokens via POST to the token endpoint.
   */
  async handleCallback(
    code: string,
    config: OAuthProviderConfig,
    redirectUri: string,
    codeVerifier: string,
  ): Promise<TokenExchangeResult> {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: config.client_id,
      code_verifier: codeVerifier,
    });
    if (config.client_secret) {
      params.set("client_secret", config.client_secret);
    }

    let response: Response;
    try {
      response = await fetch(config.token_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: params.toString(),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      throw VaultError.oauthTokenExchangeFailed(
        err instanceof Error ? err.message : "Network error",
      );
    }

    if (!response.ok) {
      throw VaultError.oauthTokenExchangeFailed(
        `Token endpoint returned HTTP ${response.status}`,
      );
    }

    let body: Record<string, unknown>;
    try {
      body = (await response.json()) as Record<string, unknown>;
    } catch {
      throw VaultError.oauthTokenExchangeFailed("Invalid JSON response from token endpoint");
    }

    const accessToken = body.access_token as string | undefined;
    if (!accessToken) {
      throw VaultError.oauthTokenExchangeFailed("No access_token in response");
    }

    return {
      access_token: accessToken,
      refresh_token: (body.refresh_token as string) ?? undefined,
      expires_in: typeof body.expires_in === "number" ? body.expires_in : undefined,
    };
  }
}
