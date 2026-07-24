import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VaultEngine } from "@harpoc/core";
import type { ScopeGuard } from "../guards/scope-guard.js";

export function registerSecretsResource(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
): void {
  // Static: list all secrets
  server.resource(
    "secrets-list",
    "secret://vault/secrets",
    {
      description: "List of all secret handles with metadata (never values)",
      mimeType: "application/json",
    },
    async (uri) => {
      scopeGuard.checkAccess("list");
      const secrets = scopeGuard.filterByScope(engine.listSecrets(undefined, scopeGuard.caller));
      const result = secrets.map((s) => ({
        handle: s.handle,
        name: s.name,
        type: s.type,
        project: s.project,
        status: s.status,
        version: s.version,
      }));
      return {
        contents: [
          { uri: uri.href, mimeType: "application/json", text: JSON.stringify(result, null, 2) },
        ],
      };
    },
  );

  // Template: single secret by name
  server.resource(
    "secret-by-name",
    new ResourceTemplate("secret://vault/secrets/{name}", {
      list: async () => {
        scopeGuard.checkAccess("list");
        const secrets = scopeGuard.filterByScope(engine.listSecrets(undefined, scopeGuard.caller));
        return {
          resources: secrets.map((s) => ({
            uri: `secret://vault/secrets/${s.name}`,
            name: s.name,
            description: `Secret: ${s.name} (${s.type}, ${s.status})`,
            mimeType: "application/json",
          })),
        };
      },
    }),
    {
      description: "Metadata for a specific secret (never the value)",
      mimeType: "application/json",
    },
    async (uri, variables) => {
      const name = variables.name as string;
      scopeGuard.checkAccess("read", undefined, name);

      // The template variable is a bare name, which does not resolve to a
      // handle for project-scoped secrets — so the listing (unfiltered, no
      // caller) is used only to map name → handle. Nothing from it is
      // returned: the metadata comes from getSecretInfo, which applies the
      // per-secret `read` gate this resource used to sidestep by answering
      // straight out of the list.
      const located = engine.listSecrets().find((s) => s.name === name);
      if (!located) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "application/json",
              text: JSON.stringify({ error: "Secret not found" }),
            },
          ],
        };
      }

      const secret = await engine.getSecretInfo(located.handle, scopeGuard.caller);
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(
              {
                handle: secret.handle,
                name: secret.name,
                type: secret.type,
                project: secret.project,
                status: secret.status,
                version: secret.version,
                created_at: secret.createdAt,
                updated_at: secret.updatedAt,
                expires_at: secret.expiresAt,
                rotated_at: secret.rotatedAt,
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
