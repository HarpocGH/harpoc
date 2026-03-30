import { VaultError } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { getScopesSeparator } from "../providers.js";

export interface ClientCredentialsResult {
  access_token: string;
  expires_in?: number;
}

export class ClientCredentialsFlow {
  /**
   * Authenticate via client_credentials grant.
   * POST to token_endpoint with client_id + client_secret.
   */
  async authenticate(config: OAuthProviderConfig): Promise<ClientCredentialsResult> {
    if (!config.client_secret) {
      throw VaultError.oauthFlowFailed("client_secret is required for client_credentials flow");
    }

    const params = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: config.client_id,
      client_secret: config.client_secret,
    });

    if (config.scopes && config.scopes.length > 0) {
      const separator = getScopesSeparator(config.provider);
      params.set("scope", config.scopes.join(separator));
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
      expires_in: typeof body.expires_in === "number" ? body.expires_in : undefined,
    };
  }
}
