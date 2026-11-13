import type { McpServer } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import { AuditEventType } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

export function registerAuditResource(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.registerResource(
    "audit-recent",
    "secret://vault/audit/recent",
    {
      description: "Last 50 audit log entries, reads excluded (metadata only)",
      mimeType: "application/json",
    },
    async (uri) => {
      scopeGuard.checkAccess("admin", undefined, undefined, `resources/read ${uri.href}`);
      rateLimiter.checkLimit();

      // Scoped admin tokens see only rows about secrets they can address (L10).
      const events = engine.queryAudit(
        { limit: 50, excludeEventType: AuditEventType.VAULT_READ },
        scopeGuard.auditScope,
        scopeGuard.caller,
      );
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
