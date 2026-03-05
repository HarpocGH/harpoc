import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VaultEngine } from "@harpoc/core";
import type { ScopeGuard } from "../guards/scope-guard.js";

const EXPIRING_SOON_DAYS = 7;

export function registerHealthResource(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
): void {
  server.resource(
    "vault-health",
    "secret://vault/health",
    { description: "Vault state and secret health summary", mimeType: "application/json" },
    async (uri) => {
      scopeGuard.checkAccess("list");

      const secrets = scopeGuard.filterByScope(engine.listSecrets());
      const byStatus: Record<string, number> = {};
      const expiringSoon: Array<{ handle: string; expires_at: number }> = [];
      const now = Date.now();
      const threshold = now + EXPIRING_SOON_DAYS * 24 * 60 * 60 * 1000;

      for (const s of secrets) {
        byStatus[s.status] = (byStatus[s.status] ?? 0) + 1;
        if (s.expiresAt && s.expiresAt <= threshold && s.status === "active") {
          expiringSoon.push({ handle: s.handle, expires_at: s.expiresAt });
        }
      }

      return {
        contents: [{
          uri: uri.href,
          mimeType: "application/json",
          text: JSON.stringify({
            vault_state: engine.getState(),
            total_secrets: secrets.length,
            by_status: byStatus,
            expiring_soon: expiringSoon,
          }, null, 2),
        }],
      };
    },
  );
}
