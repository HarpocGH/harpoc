import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VaultEngine } from "@harpoc/core";
import type { ScopeGuard } from "../guards/scope-guard.js";

export function registerAuditResource(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
): void {
  server.resource(
    "audit-recent",
    "secret://vault/audit/recent",
    { description: "Last 50 audit log entries (metadata only)", mimeType: "application/json" },
    async (uri) => {
      scopeGuard.checkAccess("admin");

      const events = engine.queryAudit({ limit: 50 });
      const result = events.map((e) => ({
        id: e.id,
        timestamp: e.timestamp,
        event_type: e.event_type,
        secret_id: e.secret_id,
        principal_type: e.principal_type,
        principal_id: e.principal_id,
        success: e.success,
        detail: e.detail,
      }));

      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );
}
