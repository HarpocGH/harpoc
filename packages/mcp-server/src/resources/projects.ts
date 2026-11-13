import type { McpServer } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

export function registerProjectsResource(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.registerResource(
    "projects",
    "secret://vault/projects",
    { description: "Distinct projects with secret counts", mimeType: "application/json" },
    async (uri) => {
      scopeGuard.checkAccess("list", undefined, undefined, `resources/read ${uri.href}`);
      rateLimiter.checkLimit();

      const secrets = scopeGuard.filterByScope(engine.listSecrets(undefined, scopeGuard.caller));
      const counts = new Map<string, number>();

      for (const s of secrets) {
        const project = s.project ?? "(none)";
        counts.set(project, (counts.get(project) ?? 0) + 1);
      }

      const result = Array.from(counts.entries()).map(([project, count]) => ({
        project,
        secret_count: count,
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
