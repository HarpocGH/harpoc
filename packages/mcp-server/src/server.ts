import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CertManager } from "@harpoc/cert-manager";
import type { VaultEngine } from "@harpoc/core";
import { OAuthManager } from "@harpoc/oauth-proxy";
import type { AccessInterface } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { InjectionGuard } from "./guards/injection-guard.js";
import { RateLimiter } from "./guards/rate-limiter.js";
import { ScopeGuard } from "./guards/scope-guard.js";
import { registerCheckHealth } from "./tools/check-health.js";
import { registerCreateSecret } from "./tools/create-secret.js";
import { registerGetSecretInfo } from "./tools/get-secret-info.js";
import { registerListSecrets } from "./tools/list-secrets.js";
import { registerRenewCertificate } from "./tools/renew-certificate.js";
import { registerRevokeSecret } from "./tools/revoke-secret.js";
import { registerRotateSecret } from "./tools/rotate-secret.js";
import { registerStartOauthFlow } from "./tools/start-oauth-flow.js";
import { registerUseSecret } from "./tools/use-secret.js";
import { registerAuditResource } from "./resources/audit.js";
import { registerHealthResource } from "./resources/health.js";
import { registerProjectsResource } from "./resources/projects.js";
import { registerSecretsResource } from "./resources/secrets.js";

export interface CreateMcpServerOptions {
  engine: VaultEngine;
  launchToken?: string;
  /**
   * Explicitly accept the unrestricted local full-access mode when no launch
   * token is provided (thesis alignment V3: the handle+token pair is the
   * access model, so tokenless operation must be a deliberate operator
   * decision, never a silent default). Without a token and without this flag,
   * construction throws TOKEN_REQUIRED. Set only by the stdio entry points'
   * --allow-tokenless flag — the Streamable HTTP transport always carries a
   * per-request token and never sets it.
   *
   * Taking this branch writes a `server.start` audit row (W6) and fails closed
   * if that row cannot be written.
   */
  allowTokenless?: boolean;
  /** Shared across per-session servers (Streamable HTTP) so limits span sessions. */
  rateLimiter?: RateLimiter;
  injectionGuard?: InjectionGuard;
  /**
   * Shared across per-session servers like `rateLimiter`: the manager owns the
   * in-flight background flows (device-code polls), so one instance per
   * transport keeps them cancellable across sessions.
   */
  oauthManager?: OAuthManager;
  certManager?: CertManager;
  /**
   * Allow create/rotate to fall back to a masked prompt on the controlling
   * terminal (thesis value-collection channel 2). Only stdio entry points
   * enable this — never the Streamable HTTP transport, whose clients are
   * remote from the vault host's terminal.
   */
  enableTtyPrompt?: boolean;
  /**
   * Which MCP transport this server serves — stamped on the token-derived
   * caller for audit attribution ("through which interface", thesis §4.3.4).
   * Stdio entry points keep the default; the Streamable HTTP listener passes
   * "mcp-http" per session.
   */
  accessInterface?: Extract<AccessInterface, "mcp" | "mcp-http">;
}

/**
 * The OAuth manager an MCP host runs with: MCP never drives the browser leg
 * (D1) — the CLI does — and a background flow's failure is reported on stderr,
 * never through the model's channel. Exported so the Streamable HTTP transport
 * can share ONE instance across its per-session servers: the manager owns the
 * in-flight device-code polls, which must stay cancellable across sessions.
 */
export function createDefaultOAuthManager(engine: VaultEngine): OAuthManager {
  return new OAuthManager(engine, {
    openBrowser: async () => {},
    onBackgroundFlowError: (secretId, err) =>
      process.stderr.write(
        `[harpoc] OAuth background flow failed (${secretId}): ${err instanceof Error ? err.message : String(err)}\n`,
      ),
  });
}

/**
 * Create and configure the Harpoc MCP server with all tools and resources.
 * If a launch token is provided, it is verified and used for scope enforcement.
 * Without a token, construction is refused (TOKEN_REQUIRED) unless the caller
 * explicitly opts into the unrestricted local full-access mode via
 * `allowTokenless` — which is audited as `server.start`, fail-closed.
 */
export function createMcpServer(options: CreateMcpServerOptions): McpServer {
  const { engine, launchToken } = options;

  const accessInterface = options.accessInterface ?? "mcp";

  let scopeGuard: ScopeGuard;
  if (launchToken) {
    const token = engine.verifyToken(launchToken);
    // Revocation is re-consulted per call: this token is verified once, here,
    // and the server it launches can outlive the operator's decision to revoke
    // it (H7). The HTTP transport re-verifies per request and needs no hook.
    scopeGuard = new ScopeGuard(token, accessInterface, (jti) => engine.isTokenRevoked(jti));
  } else if (options.allowTokenless) {
    // The waiver goes into the tamper-evident trail before anything else
    // happens (W6): a failed write must leave neither a warning on stderr nor
    // a constructed server behind — no record, no unrestricted server.
    engine.auditServerStart({
      transport: "stdio",
      tokenless: true,
      ttyPrompt: options.enableTtyPrompt ?? false,
    });
    process.stderr.write(
      "[harpoc] WARNING: --allow-tokenless — all tools and resources are unrestricted (no launch token)\n",
    );
    scopeGuard = new ScopeGuard(null, accessInterface);
  } else {
    // The refusal is as much a start decision as the waiver: without a row the
    // trail shows nothing at all for a launch that was attempted and denied.
    engine.auditServerStart({
      transport: "stdio",
      tokenless: false,
      ttyPrompt: options.enableTtyPrompt ?? false,
      success: false,
      error: ErrorCode.TOKEN_REQUIRED,
    });
    throw VaultError.tokenRequired();
  }

  const rateLimiter = options.rateLimiter ?? new RateLimiter();
  const injectionGuard = options.injectionGuard ?? new InjectionGuard();
  const oauthManager = options.oauthManager ?? createDefaultOAuthManager(engine);
  const certManager = options.certManager ?? new CertManager(engine);

  const server = new McpServer(
    { name: "harpoc", version: "0.0.0" },
    {
      capabilities: {
        tools: { listChanged: false },
        resources: { subscribe: false, listChanged: false },
      },
    },
  );

  const enableTtyPrompt = options.enableTtyPrompt ?? false;

  // Register tools
  registerListSecrets(server, engine, scopeGuard, rateLimiter);
  registerGetSecretInfo(server, engine, scopeGuard, rateLimiter);
  registerUseSecret(server, engine, scopeGuard, rateLimiter, injectionGuard);
  registerCreateSecret(server, engine, scopeGuard, rateLimiter, enableTtyPrompt);
  registerRotateSecret(server, engine, scopeGuard, rateLimiter, enableTtyPrompt);
  registerRevokeSecret(server, engine, scopeGuard, rateLimiter);
  registerCheckHealth(server, engine, scopeGuard, rateLimiter);
  registerStartOauthFlow(server, engine, scopeGuard, rateLimiter, oauthManager, enableTtyPrompt);
  registerRenewCertificate(server, engine, scopeGuard, rateLimiter, certManager);

  // Register resources
  registerSecretsResource(server, engine, scopeGuard);
  registerHealthResource(server, engine, scopeGuard);
  registerAuditResource(server, engine, scopeGuard);
  registerProjectsResource(server, engine, scopeGuard);

  return server;
}
