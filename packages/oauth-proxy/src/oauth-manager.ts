import type { VaultEngine } from "@harpoc/core";
import type { CallerContext, OAuthFlowResult, OAuthProviderConfig } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { AuthorizationCodeFlow, buildAuthorizationUrl } from "./flows/authorization-code.js";
import { ClientCredentialsFlow } from "./flows/client-credentials.js";
import { DeviceCodeFlow } from "./flows/device-code.js";
import { CallbackServer } from "./callback-server.js";
import type { CallbackResult } from "./callback-server.js";
import { generateCodeChallenge } from "./pkce.js";
import { resolveProvider } from "./providers.js";

export interface OAuthManagerOptions {
  openBrowser?: (url: string) => Promise<void>;
  callbackPort?: number;
  callbackTimeoutMs?: number;
  /**
   * Called when a background device-code flow fails after the initial
   * response has been returned (the secret stays PENDING). Default: no-op —
   * the package stays console-free; the host decides how to report.
   */
  onBackgroundFlowError?: (secretId: string, err: unknown) => void;
  /**
   * Ceiling on concurrently pending authorization-code flows, each of which
   * holds a loopback callback listener until the redirect arrives or the
   * callback times out. Default {@link DEFAULT_MAX_PENDING_AUTHORIZATIONS}.
   * Device-code flows hold no socket and are not counted.
   */
  maxPendingAuthorizations?: number;
}

/** Default ceiling on socket-holding authorization-code flows (D3). */
export const DEFAULT_MAX_PENDING_AUTHORIZATIONS = 32;

/**
 * A registered background flow. `holdsSocket` marks the authorization-code
 * flows — the ones that pin a loopback listener and a timeout timer for the
 * whole callback window, and therefore the ones the cap counts.
 */
interface PendingFlow {
  controller: AbortController;
  holdsSocket: boolean;
  /** Set by the completer before it unregisters: this flow can no longer run. */
  settled: boolean;
}

/**
 * Result of starting a device-code flow. `completion` settles when the
 * background poll finishes: resolves once the secret is ACTIVE, rejects on
 * poll failure/timeout/abort. Safe to ignore (rejections are marked handled
 * internally and routed to onBackgroundFlowError). Never serialize this into
 * wire output — the promise serializes as `{}`; hosts build their own shape.
 */
export interface DeviceCodeFlowResult extends OAuthFlowResult {
  completion: Promise<void>;
}

/**
 * Result of a non-blocking authorization-code start: the callback server is
 * listening and `authUrl` is ready for the user, while `completion` settles
 * when the redirect arrives and the code has been exchanged (resolves once the
 * secret is ACTIVE; rejects on callback timeout/exchange failure/abort). Safe
 * to ignore — rejections are marked handled internally and routed to
 * onBackgroundFlowError. Never serialize this: the promise serializes as `{}`.
 */
export interface AuthorizationCodeStart {
  handle: string;
  secretId: string;
  authUrl: string;
  completion: Promise<void>;
}

/** System-browser opener (the constructor default); exported so hosts can gate it behind a flag. */
export async function defaultOpenBrowser(url: string): Promise<void> {
  const openModule = await import("open");
  await openModule.default(url);
}

function toFlowError(err: unknown): VaultError {
  return err instanceof VaultError
    ? err
    : VaultError.oauthFlowFailed(err instanceof Error ? err.message : "Unknown error");
}

/**
 * Race the OAuth redirect (or the callback server's own timeout/invalid-state
 * rejection) against an abort from cancelFlow/cancelPendingFlows. An abort also
 * stops the server: no redirect can be honoured once the flow is cancelled.
 */
function waitForCallbackOrAbort(
  callbackServer: CallbackServer,
  signal: AbortSignal,
): Promise<CallbackResult> {
  return new Promise<CallbackResult>((resolve, reject) => {
    const onAbort = (): void => {
      void callbackServer.stop();
      reject(VaultError.oauthFlowFailed("Authorization flow aborted"));
    };
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    callbackServer.waitForCallback().then(
      (result) => {
        signal.removeEventListener("abort", onAbort);
        resolve(result);
      },
      (err: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(toFlowError(err));
      },
    );
  });
}

/**
 * `client_secret_basic` puts the client credentials in an Authorization
 * header; without a secret there is nothing to put there and the helper would
 * fall through to a public-client body — an RFC-consistent fall-through for
 * refresh, but a configuration mistake at flow start (R11/B26, 2026-09-04).
 * Checked on the resolved config, after the preset merge and before the
 * pending secret is created, so no row and no network precede the refusal.
 */
function assertAuthMethodPairing(config: OAuthProviderConfig): void {
  if (
    config.token_endpoint_auth_method === "client_secret_basic" &&
    (config.client_secret === undefined || config.client_secret === "")
  ) {
    throw VaultError.invalidInput(
      "client_secret_basic requires a client secret: the method sends the client credentials in an Authorization header, which a public client cannot form — supply the secret, or choose client_secret_post (the default) for a public client",
    );
  }
}

export class OAuthManager {
  private engine: VaultEngine;
  private openBrowser: (url: string) => Promise<void>;
  private callbackPort: number;
  private callbackTimeoutMs: number;
  private onBackgroundFlowError?: (secretId: string, err: unknown) => void;
  private maxPendingAuthorizations: number;
  private readonly pendingFlows = new Map<string, PendingFlow>();

  constructor(engine: VaultEngine, options?: OAuthManagerOptions) {
    this.engine = engine;
    this.openBrowser = options?.openBrowser ?? defaultOpenBrowser;
    this.callbackPort = options?.callbackPort ?? 19876;
    this.callbackTimeoutMs = options?.callbackTimeoutMs ?? 5 * 60 * 1000;
    this.onBackgroundFlowError = options?.onBackgroundFlowError;
    // A non-finite cap would make every `count >= max` comparison false, i.e.
    // silently disable the control — the one fail-open direction here.
    const requestedMax = options?.maxPendingAuthorizations;
    this.maxPendingAuthorizations =
      requestedMax !== undefined && Number.isFinite(requestedMax)
        ? requestedMax
        : DEFAULT_MAX_PENDING_AUTHORIZATIONS;
  }

  /**
   * Abort one pending background flow — a device-code poll, or an
   * authorization-code flow from its reservation onward (bind window included).
   */
  cancelFlow(secretId: string): boolean {
    const flow = this.pendingFlows.get(secretId);
    if (!flow) return false;
    flow.controller.abort();
    return true;
  }

  /**
   * Abort every pending background flow, device-code polls and
   * authorization-code flows alike (owner dispose path).
   */
  cancelPendingFlows(): void {
    for (const flow of this.pendingFlows.values()) {
      flow.controller.abort();
    }
  }

  /** Pending flows currently pinning a loopback callback listener. */
  private countSocketFlows(): number {
    let count = 0;
    for (const flow of this.pendingFlows.values()) {
      if (flow.holdsSocket) count++;
    }
    return count;
  }

  /**
   * Start an authorization_code flow without blocking on the user:
   * 1. Create OAuth secret in vault (PENDING)
   * 2. Start callback server (to get the bound port)
   * 3. Generate PKCE pair + state, construct auth URL
   * 4. Return handle + auth URL; steps 5–7 run in the background
   * 5. Wait for callback with auth code
   * 6. Exchange code for tokens
   * 7. Complete OAuth flow (secret → ACTIVE)
   *
   * The flow is registered in `pendingFlows`, so `cancelFlow`/`cancelPendingFlows`
   * abort it and stop the callback server. A failing flow leaves the secret
   * PENDING — the user can retry or delete it.
   */
  async startAuthorizationCodeDeferred(
    name: string,
    config: OAuthProviderConfig,
    project?: string,
    caller?: CallerContext,
  ): Promise<AuthorizationCodeStart> {
    const resolved = resolveProvider(config);
    assertAuthMethodPairing(resolved);
    const { handle, secretId } = await this.engine.createOAuthSecret(
      name,
      resolved,
      project,
      caller,
    );

    // Cap the concurrently pinned loopback listeners (D3). Checked here — the
    // secretId is known, so a supersede (same secret, its predecessor already
    // holding a socket that this start replaces) is exempt — and before the
    // CallbackServer exists, so a refusal binds no socket and arms no timer.
    // The PENDING secret row above stays and is resumable: that row is what
    // `create` scope already buys.
    const predecessor = this.pendingFlows.get(secretId);
    if (
      predecessor?.holdsSocket !== true &&
      this.countSocketFlows() >= this.maxPendingAuthorizations
    ) {
      throw new VaultError(ErrorCode.RATE_LIMIT_EXCEEDED, "Too many pending authorization flows");
    }

    // Reserve the slot before the bind (D9): a fresh start counts toward the
    // cap from here, and cancelFlow during the bind window aborts this very
    // controller. A supersede overwrites the predecessor's entry but aborts it
    // only once the successor is bound, so two starts never race one port.
    // A failed bind rolls back only its own entry, onto a live predecessor only
    // — and rolls back nothing once the reservation itself has been aborted,
    // which cancels the predecessor it displaced along with it.
    const controller = new AbortController();
    const pending: PendingFlow = { controller, holdsSocket: true, settled: false };
    this.pendingFlows.set(secretId, pending);

    const callbackServer = new CallbackServer(this.callbackPort);
    const flow = new AuthorizationCodeFlow();

    try {
      // Generate PKCE pair + state. We need the state for the callback server.
      // Use a temporary redirectUri — we'll adjust after the server is listening.
      const tempRedirectUri =
        resolved.redirect_uri ?? `http://localhost:${this.callbackPort}/oauth/callback`;
      const { state, code_verifier } = flow.startFlow(resolved, tempRedirectUri);

      await callbackServer.start(state, this.callbackTimeoutMs);
      predecessor?.controller.abort();

      // Final redirect URI carries the actually bound port (callbackPort 0)
      const redirectUri =
        resolved.redirect_uri ?? `http://localhost:${callbackServer.listenPort}/oauth/callback`;
      const authUrl = buildAuthorizationUrl(
        resolved,
        redirectUri,
        state,
        generateCodeChallenge(code_verifier),
      );

      const completion = this.completeAuthorizationCodeInBackground(
        flow,
        callbackServer,
        resolved,
        redirectUri,
        code_verifier,
        secretId,
        pending,
      );

      return { handle, secretId, authUrl, completion };
    } catch (err) {
      if (this.pendingFlows.get(secretId)?.controller === controller) {
        if (controller.signal.aborted) {
          predecessor?.controller.abort();
          this.pendingFlows.delete(secretId);
        } else if (predecessor && !predecessor.controller.signal.aborted && !predecessor.settled) {
          this.pendingFlows.set(secretId, predecessor);
        } else {
          this.pendingFlows.delete(secretId);
        }
      }
      await callbackServer.stop();
      throw toFlowError(err);
    }
  }

  /**
   * Blocking authorization_code flow: the deferred start plus opening the
   * browser and awaiting the exchange.
   */
  async startAuthorizationCode(
    name: string,
    config: OAuthProviderConfig,
    project?: string,
    caller?: CallerContext,
  ): Promise<OAuthFlowResult> {
    const start = await this.startAuthorizationCodeDeferred(name, config, project, caller);

    try {
      await this.openBrowser(start.authUrl);
    } catch (err) {
      // No browser means no callback will ever arrive: abort the flow (which
      // stops the callback server) instead of leaving it pending.
      this.cancelFlow(start.secretId);
      throw toFlowError(err);
    }

    await start.completion;

    return {
      handle: start.handle,
      status: "authorized",
      message: `OAuth flow completed successfully for ${config.provider}`,
    };
  }

  private completeAuthorizationCodeInBackground(
    flow: AuthorizationCodeFlow,
    callbackServer: CallbackServer,
    resolved: OAuthProviderConfig,
    redirectUri: string,
    codeVerifier: string,
    secretId: string,
    pending: PendingFlow,
  ): Promise<void> {
    const completion = (async () => {
      try {
        const { code } = await waitForCallbackOrAbort(callbackServer, pending.controller.signal);
        const tokens = await flow.handleCallback(code, resolved, redirectUri, codeVerifier);
        const expiresAt = tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined;
        await this.engine.completeOAuthFlow(
          secretId,
          tokens.access_token,
          tokens.refresh_token,
          expiresAt,
        );
      } catch (err) {
        throw toFlowError(err);
      } finally {
        await callbackServer.stop();
      }
    })();
    // Derived chain: keeps onBackgroundFlowError semantics AND marks the
    // rejection handled, so an unawaited `completion` never becomes an
    // unhandled rejection.
    completion
      .catch((err: unknown) => {
        // An abort is an expected cancellation; anything else (callback
        // timeout, token exchange failure, completeOAuthFlow on a sealed
        // engine) is surfaced — the secret stays PENDING either way.
        if (!pending.controller.signal.aborted) {
          try {
            this.onBackgroundFlowError?.(secretId, err);
          } catch {
            // An embedder callback that throws must not poison the derived
            // chain — the chain exists precisely to keep rejections observed.
          }
        }
      })
      .finally(() => {
        pending.settled = true;
        this.unregisterPendingFlow(secretId, pending.controller);
      });
    return completion;
  }

  /**
   * Register a socket-less background flow (device code) under its secretId,
   * superseding any flow already running for that secret — the
   * authorization-code path reserves its own entry before the bind instead
   * (D9). `createOAuthSecret` resumes a PENDING secret and returns the SAME
   * secretId, so a second start for the same name would otherwise leave the
   * first flow live but uncancellable — still able to exchange a redirect and
   * drive the secret ACTIVE behind the caller's back.
   */
  private registerPendingFlow(secretId: string): PendingFlow {
    this.pendingFlows.get(secretId)?.controller.abort();
    const pending: PendingFlow = {
      controller: new AbortController(),
      holdsSocket: false,
      settled: false,
    };
    this.pendingFlows.set(secretId, pending);
    return pending;
  }

  /** Drop a settled flow's entry — never a successor's (same-secretId restart). */
  private unregisterPendingFlow(secretId: string, controller: AbortController): void {
    if (this.pendingFlows.get(secretId)?.controller === controller) {
      this.pendingFlows.delete(secretId);
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
    caller?: CallerContext,
  ): Promise<OAuthFlowResult> {
    const resolved = resolveProvider(config);
    assertAuthMethodPairing(resolved);
    const { handle, secretId } = await this.engine.createOAuthSecret(
      name,
      resolved,
      project,
      caller,
    );

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
      throw toFlowError(err);
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
    caller?: CallerContext,
  ): Promise<DeviceCodeFlowResult> {
    const resolved = resolveProvider(config);
    assertAuthMethodPairing(resolved);
    const { handle, secretId } = await this.engine.createOAuthSecret(
      name,
      resolved,
      project,
      caller,
    );

    const flow = new DeviceCodeFlow();
    const deviceResult = await flow.startFlow(resolved);

    // Start polling in the background (non-blocking)
    const completion = this.pollDeviceCodeInBackground(
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
      completion,
    };
  }

  private pollDeviceCodeInBackground(
    flow: DeviceCodeFlow,
    deviceCode: string,
    interval: number,
    config: OAuthProviderConfig,
    expiresIn: number,
    secretId: string,
  ): Promise<void> {
    // A device-code poll holds no listener: registered for cancellation, but
    // outside the authorization cap.
    const pending = this.registerPendingFlow(secretId);
    const completion = flow
      .pollForToken(deviceCode, interval, config, expiresIn, pending.controller.signal)
      .then(async (tokens) => {
        const expiresAt = tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined;
        await this.engine.completeOAuthFlow(
          secretId,
          tokens.access_token,
          tokens.refresh_token,
          expiresAt,
        );
      });
    // Derived chain: keeps onBackgroundFlowError semantics AND marks the
    // rejection handled, so an unawaited `completion` never becomes an
    // unhandled rejection.
    completion
      .catch((err: unknown) => {
        // An abort is an expected cancellation; anything else (poll failure,
        // timeout, completeOAuthFlow on a sealed engine) is surfaced — the
        // secret stays PENDING either way.
        if (!pending.controller.signal.aborted) {
          try {
            this.onBackgroundFlowError?.(secretId, err);
          } catch {
            // An embedder callback that throws must not poison the derived
            // chain — the chain exists precisely to keep rejections observed.
          }
        }
      })
      .finally(() => {
        pending.settled = true;
        this.unregisterPendingFlow(secretId, pending.controller);
      });
    return completion;
  }
}
