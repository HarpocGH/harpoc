import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VaultEngine } from "@harpoc/core";
import type { ScopeGuard } from "../guards/scope-guard.js";

export function registerProjectsResource(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
): void {
  server.resource(
    "projects",
    "secret://vault/projects",
    { description: "Distinct projects with secret counts", mimeType: "application/json" },
    async (uri) => {
      scopeGuard.checkAccess("list");

      const secrets = scopeGuard.filterByScope(engine.listSecrets());
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
