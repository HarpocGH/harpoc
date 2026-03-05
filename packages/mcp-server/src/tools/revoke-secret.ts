import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "revoke";

export function registerRevokeSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.tool(
    "revoke_secret",
    "Permanently revoke a secret (cannot be undone)",
    {
      handle: z.string().describe("Secret handle to revoke"),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);
      rateLimiter.checkLimit();

      await engine.revokeSecret(args.handle);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                handle: args.handle,
                status: "revoked",
                message: "Secret has been permanently revoked",
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
