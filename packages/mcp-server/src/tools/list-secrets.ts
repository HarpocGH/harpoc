import type { McpServer } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";
import { LIST_SECRETS_TOOL } from "./definitions.js";

const PERMISSION: Permission = "list";

export function registerListSecrets(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.registerTool(LIST_SECRETS_TOOL.name, LIST_SECRETS_TOOL.config, async (args) => {
    scopeGuard.checkAccess(PERMISSION, args.project, undefined, "list_secrets");
    rateLimiter.checkLimit();

    let secrets = engine.listSecrets(args.project, scopeGuard.caller);

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
  });
}
