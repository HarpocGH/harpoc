import { validateUrl } from "@harpoc/core";
import { VaultError, applyTokenEndpointAuth } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { getScopesSeparator } from "../providers.js";

export interface DeviceCodeStartResult {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

export interface DeviceCodeTokenResult {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

export class DeviceCodeFlow {
  /**
   * Start the device code flow by requesting a device code from the provider.
   */
  async startFlow(config: OAuthProviderConfig): Promise<DeviceCodeStartResult> {
    if (!config.device_authorization_endpoint) {
      throw VaultError.oauthFlowFailed(
        "device_authorization_endpoint is required for device_code flow",
      );
    }

    const params = new URLSearchParams({
      client_id: config.client_id,
    });

    if (config.scopes && config.scopes.length > 0) {
      const separator = getScopesSeparator(config.provider);
      params.set("scope", config.scopes.join(separator));
    }

    await validateUrl(config.device_authorization_endpoint);

    let response: Response;
    try {
      response = await fetch(config.device_authorization_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: params.toString(),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      throw VaultError.oauthFlowFailed(err instanceof Error ? err.message : "Network error");
    }

    if (!response.ok) {
      throw VaultError.oauthFlowFailed(
        `Device authorization endpoint returned HTTP ${response.status}`,
      );
    }

    let body: Record<string, unknown>;
    try {
      body = (await response.json()) as Record<string, unknown>;
    } catch {
      throw VaultError.oauthFlowFailed("Invalid JSON response from device authorization endpoint");
    }

    const deviceCode = body.device_code as string | undefined;
    const userCode = body.user_code as string | undefined;
    const verificationUri = body.verification_uri as string | undefined;

    if (!deviceCode || !userCode || !verificationUri) {
      throw VaultError.oauthFlowFailed(
        "Missing device_code, user_code, or verification_uri in response",
      );
    }

    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: (body.verification_uri_complete as string) ?? undefined,
      expires_in: typeof body.expires_in === "number" ? body.expires_in : 900,
      interval: typeof body.interval === "number" ? body.interval : 5,
    };
  }

  /**
   * Poll the token endpoint until authorization is granted, denied, or expired.
   * Respects the polling interval and handles slow_down responses.
   */
  async pollForToken(
    deviceCode: string,
    interval: number,
    config: OAuthProviderConfig,
    expiresIn: number,
    signal?: AbortSignal,
  ): Promise<DeviceCodeTokenResult> {
    await validateUrl(config.token_endpoint);

    let currentInterval = interval;
    const deadline = Date.now() + expiresIn * 1000;

    while (Date.now() < deadline) {
      if (signal?.aborted) {
        throw VaultError.oauthFlowFailed("Polling aborted");
      }

      await this.sleep(currentInterval * 1000, signal);

      if (signal?.aborted) {
        throw VaultError.oauthFlowFailed("Polling aborted");
      }

      const params = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
      });
      const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      };
      applyTokenEndpointAuth(config, params, headers);

      let response: Response;
      try {
        response = await fetch(config.token_endpoint, {
          method: "POST",
          headers,
          body: params.toString(),
          signal: AbortSignal.timeout(30_000),
        });
      } catch (err) {
        throw VaultError.oauthFlowFailed(err instanceof Error ? err.message : "Network error");
      }

      let body: Record<string, unknown>;
      try {
        body = (await response.json()) as Record<string, unknown>;
      } catch {
        throw VaultError.oauthFlowFailed("Invalid JSON response from token endpoint");
      }

      if (response.ok && body.access_token) {
        return {
          access_token: body.access_token as string,
          refresh_token: (body.refresh_token as string) ?? undefined,
          expires_in: typeof body.expires_in === "number" ? body.expires_in : undefined,
        };
      }

      const error = body.error as string | undefined;
      if (error === "authorization_pending") {
        continue;
      } else if (error === "slow_down") {
        currentInterval += 5;
        continue;
      } else if (error === "access_denied") {
        throw VaultError.oauthFlowFailed("User denied authorization");
      } else if (error === "expired_token") {
        throw VaultError.oauthCallbackTimeout();
      } else {
        throw VaultError.oauthFlowFailed(
          `Token endpoint error: ${error ?? `HTTP ${response.status}`}`,
        );
      }
    }

    throw VaultError.oauthCallbackTimeout();
  }

  /**
   * Abort-aware, unref'd sleep: a pending device flow must never block
   * process exit, and an abort ends the wait immediately (the caller's
   * post-sleep abort check turns it into the abort error).
   */
  private sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      if (signal?.aborted) {
        resolve();
        return;
      }
      const onAbort = (): void => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      timer.unref();
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }
}
