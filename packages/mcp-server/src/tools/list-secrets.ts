import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "list";

export function registerListSecrets(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.tool(
    "list_secrets",
    "List all secrets in the vault (metadata only, never values)",
    {
      project: z.string().optional().describe("Filter by project name"),
      type: z
        .string()
        .optional()
        .describe("Filter by secret type (api_key, oauth_token, certificate)"),
      status: z
        .string()
        .optional()
        .describe("Filter by status (active, pending, expired, revoked)"),
    },
    async (args) => {
      scopeGuard.checkAccess(PERMISSION, args.project);
      rateLimiter.checkLimit();

      let secrets = engine.listSecrets(args.project);

      // Filter by token's secret-name scope
      secrets = scopeGuard.filterByScope(secrets);

      if (args.type) {
        secrets = secrets.filter((s) => s.type === args.type);
      }
      if (args.status) {
        secrets = secrets.filter((s) => s.status === args.status);
      }

      const result = secrets.map((s) => ({
        handle: s.handle,
        name: s.name,
        type: s.type,
        project: s.project,
        status: s.status,
        version: s.version,
        created_at: s.createdAt,
        updated_at: s.updatedAt,
        expires_at: s.expiresAt,
      }));

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    },
  );
}
