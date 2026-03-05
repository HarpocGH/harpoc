import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VaultEngine } from "@harpoc/core";
import { InjectionGuard } from "./guards/injection-guard.js";
import { RateLimiter } from "./guards/rate-limiter.js";
import { ScopeGuard } from "./guards/scope-guard.js";
import { registerCheckHealth } from "./tools/check-health.js";
import { registerCreateSecret } from "./tools/create-secret.js";
import { registerGetSecretInfo } from "./tools/get-secret-info.js";
import { registerListSecrets } from "./tools/list-secrets.js";
import { registerRevokeSecret } from "./tools/revoke-secret.js";
import { registerRotateSecret } from "./tools/rotate-secret.js";
import { registerUseSecret } from "./tools/use-secret.js";
import { registerAuditResource } from "./resources/audit.js";
import { registerHealthResource } from "./resources/health.js";
import { registerProjectsResource } from "./resources/projects.js";
import { registerSecretsResource } from "./resources/secrets.js";

export interface CreateMcpServerOptions {
  engine: VaultEngine;
  launchToken?: string;
}

/**
 * Create and configure the Harpoc MCP server with all tools and resources.
 * If a launch token is provided, it is verified and used for scope enforcement.
 * If no token, full access mode is used.
 */
export function createMcpServer(options: CreateMcpServerOptions): McpServer {
  const { engine, launchToken } = options;

  // Validate launch token if provided
  let scopeGuard: ScopeGuard;
  if (launchToken) {
    const token = engine.verifyToken(launchToken);
    scopeGuard = new ScopeGuard(token);
  } else {
    process.stderr.write("[harpoc] WARNING: No launch token provided — all tools and resources are unrestricted\n");
    scopeGuard = new ScopeGuard(null);
  }

  const rateLimiter = new RateLimiter();
  const injectionGuard = new InjectionGuard();

  const server = new McpServer(
    { name: "harpoc", version: "0.0.0" },
    {
      capabilities: {
        tools: { listChanged: false },
        resources: { subscribe: false, listChanged: false },
      },
    },
  );

  // Register tools
  registerListSecrets(server, engine, scopeGuard, rateLimiter);
  registerGetSecretInfo(server, engine, scopeGuard, rateLimiter);
  registerUseSecret(server, engine, scopeGuard, rateLimiter, injectionGuard);
  registerCreateSecret(server, engine, scopeGuard, rateLimiter);
  registerRotateSecret(server, engine, scopeGuard, rateLimiter);
  registerRevokeSecret(server, engine, scopeGuard, rateLimiter);
  registerCheckHealth(server, engine, scopeGuard, rateLimiter);

  // Register resources
  registerSecretsResource(server, engine, scopeGuard);
  registerHealthResource(server, engine, scopeGuard);
  registerAuditResource(server, engine, scopeGuard);
  registerProjectsResource(server, engine, scopeGuard);

  return server;
}
