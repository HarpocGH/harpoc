import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "list";
const EXPIRING_SOON_DAYS = 7;

export function registerCheckHealth(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.tool(
    "check_secret_health",
    "Check vault and secret health status",
    {
      handle: z.string().optional().describe("Optional: check a specific secret (omit for all)"),
    },
    async (args) => {
      scopeGuard.checkAccess(PERMISSION);
      rateLimiter.checkLimit();

      const secrets = engine.listSecrets();
      const filtered = args.handle ? secrets.filter((s) => s.handle === args.handle) : secrets;

      const byStatus: Record<string, number> = {};
      const expiringSoon: Array<{ handle: string; expires_at: number }> = [];
      const now = Date.now();
      const threshold = now + EXPIRING_SOON_DAYS * 24 * 60 * 60 * 1000;

      for (const s of filtered) {
        byStatus[s.status] = (byStatus[s.status] ?? 0) + 1;
        if (s.expiresAt && s.expiresAt <= threshold && s.status === "active") {
          expiringSoon.push({ handle: s.handle, expires_at: s.expiresAt });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                vault_state: engine.getState(),
                total_secrets: filtered.length,
                by_status: byStatus,
                expiring_soon: expiringSoon,
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
