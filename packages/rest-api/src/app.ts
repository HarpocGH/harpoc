import { Hono } from "hono";
import type { VaultEngine } from "@harpoc/core";
import { CertManager } from "@harpoc/cert-manager";
import { OAuthManager } from "@harpoc/oauth-proxy";
import { errorHandler } from "./middleware/error-handler.js";
import { authMiddleware } from "./middleware/auth.js";
import { RateLimiter, createRateLimitMiddleware } from "./middleware/rate-limit.js";
import { auditMiddleware } from "./middleware/audit.js";
import { createHealthRoutes, createExpiringSecretsRoute } from "./routes/health.js";
import { createSecretRoutes } from "./routes/secrets.js";
import { createPolicyRoutes } from "./routes/policies.js";
import { createAuditRoutes } from "./routes/audit.js";
import { createOAuthRoutes } from "./routes/oauth.js";
import { createCertificateRoutes } from "./routes/certificates.js";
import type { HarpocEnv } from "./types.js";

export interface CreateAppOptions {
  /**
   * Shared across every request: the manager owns the in-flight background
   * flows (device-code polls, authorization-code callbacks), so one instance
   * per app keeps them cancellable for the server's lifetime.
   */
  oauthManager?: OAuthManager;
  certManager?: CertManager;
}

/**
 * The OAuth manager a REST host runs with. Exported so the process that owns
 * the app — `harpoc server start --rest` — can construct it, hand it in, and
 * cancel its pending background flows on shutdown: a manager built inside
 * `createApp` has no dispose path, and its flows outlive the store they write
 * to.
 */
export function createDefaultOAuthManager(engine: VaultEngine): OAuthManager {
  return new OAuthManager(engine, {
    // REST never runs the browser leg (D2): the client follows auth_url itself.
    openBrowser: async () => {},
    // A long-lived server runs concurrent flows for different secrets, and a
    // re-POSTed resume flow starts a second callback server for the same
    // secret — a fixed port would EADDRINUSE-collide. Port 0 = per-flow
    // ephemeral, and the bound port is what the redirect URI carries.
    callbackPort: 0,
    onBackgroundFlowError: (secretId, err) =>
      console.error(
        `[harpoc] OAuth background flow failed (${secretId}): ${err instanceof Error ? err.message : String(err)}`,
      ),
  });
}

export function createApp(engine: VaultEngine, options?: CreateAppOptions): Hono<HarpocEnv> {
  const app = new Hono<HarpocEnv>();

  // Global error handler
  app.onError(errorHandler);

  // Rate limiter (created early so it can be injected into context)
  const limiter = new RateLimiter();

  const oauthManager = options?.oauthManager ?? createDefaultOAuthManager(engine);
  const certManager = options?.certManager ?? new CertManager(engine);

  // Inject engine, limiter and the managers into context for all routes
  app.use("*", async (c, next) => {
    c.set("engine", engine);
    c.set("limiter", limiter);
    c.set("oauthManager", oauthManager);
    c.set("certManager", certManager);
    await next();
  });

  // Health routes (no auth required, exempt from rate limiting)
  app.route("/api/v1/health", createHealthRoutes());

  // `/api/v1/secrets/*` already matches the bare collection path, so a second
  // registration for `/api/v1/secrets` runs every middleware twice on it: the
  // limiter charged two tokens per request (halving the collection route's
  // effective allowance), the audit middleware wrote the line twice and the
  // token was verified twice. One pattern per middleware.

  // Rate limiter for all non-health API routes
  app.use("/api/v1/secrets/*", createRateLimitMiddleware(limiter));
  app.use("/api/v1/audit", createRateLimitMiddleware(limiter));
  app.use("/api/v1/health/expiring", createRateLimitMiddleware(limiter));
  app.use("/api/v1/oauth/*", createRateLimitMiddleware(limiter));
  app.use("/api/v1/certificates/*", createRateLimitMiddleware(limiter));

  // Audit logging (runs after handler via await next())
  app.use("/api/v1/secrets/*", auditMiddleware);
  app.use("/api/v1/audit", auditMiddleware);
  app.use("/api/v1/oauth/*", auditMiddleware);
  app.use("/api/v1/certificates/*", auditMiddleware);

  // Auth middleware for protected routes
  app.use("/api/v1/secrets/*", authMiddleware);
  app.use("/api/v1/audit", authMiddleware);
  app.use("/api/v1/health/expiring", authMiddleware);
  app.use("/api/v1/oauth/*", authMiddleware);
  app.use("/api/v1/certificates/*", authMiddleware);

  // Routes
  app.route("/api/v1/secrets", createSecretRoutes());
  app.route("/api/v1/secrets", createPolicyRoutes());
  app.route("/api/v1/audit", createAuditRoutes());
  app.route("/api/v1/health/expiring", createExpiringSecretsRoute());
  app.route("/api/v1/oauth", createOAuthRoutes());
  app.route("/api/v1/certificates", createCertificateRoutes());

  return app;
}
