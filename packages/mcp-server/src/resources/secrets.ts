import type { McpServer } from "@modelcontextprotocol/server";
import { ResourceTemplate } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import { formatHandle, parseHandle } from "@harpoc/shared";
import type { ScopeGuard } from "../guards/scope-guard.js";

function decodeHandlePath(variable: string): string {
  try {
    return decodeURIComponent(variable);
  } catch {
    return variable;
  }
}

export function registerSecretsResource(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
): void {
  // Static: list all secrets
  server.registerResource(
    "secrets-list",
    "secret://vault/secrets",
    {
      description: "List of all secret handles with metadata (never values)",
      mimeType: "application/json",
    },
    async (uri) => {
      scopeGuard.checkAccess("list", undefined, undefined, `resources/read ${uri.href}`);
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

  // Template: single secret by handle
  server.registerResource(
    "secret-by-name",
    new ResourceTemplate("secret://vault/secrets/{name}", {
      list: async () => {
        scopeGuard.checkAccess(
          "list",
          undefined,
          undefined,
          "resources/list secret://vault/secrets/{name}",
        );
        const secrets = scopeGuard.filterByScope(engine.listSecrets(undefined, scopeGuard.caller));
        return {
          resources: secrets.map((s) => {
            const path = s.handle.slice("secret://".length);
            return {
              uri: `secret://vault/secrets/${encodeURIComponent(path)}`,
              name: s.name,
              description: `Secret: ${path} (${s.type}, ${s.status})`,
              mimeType: "application/json",
            };
          }),
        };
      },
    }),
    {
      description: "Metadata for a specific secret (never the value)",
      mimeType: "application/json",
    },
    async (uri, variables) => {
      const { project, name } = parseHandle(
        `secret://${decodeHandlePath(variables.name as string)}`,
      );
      scopeGuard.checkAccess("read", project, name, `resources/read ${uri.href}`);

      const secret = await engine.getSecretInfo(formatHandle(name, project), scopeGuard.caller);
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
