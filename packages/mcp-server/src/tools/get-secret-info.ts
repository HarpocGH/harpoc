import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "read";

export function registerGetSecretInfo(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.tool(
    "get_secret_info",
    "Get metadata for a specific secret (never returns the value)",
    {
      handle: z
        .string()
        .describe("Secret handle (e.g. secret://my-api-key or secret://project/name)"),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);
      rateLimiter.checkLimit();

      const info = await engine.getSecretInfo(args.handle);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                handle: info.handle,
                name: info.name,
                type: info.type,
                project: info.project,
                status: info.status,
                version: info.version,
                created_at: info.createdAt,
                updated_at: info.updatedAt,
                expires_at: info.expiresAt,
                rotated_at: info.rotatedAt,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );
}
