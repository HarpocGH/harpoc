import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { InjectionConfig, Permission, SecretType } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "create";

export function registerCreateSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.tool(
    "create_secret",
    "Create a new secret (value must be set separately via CLI for security — never pass secret values through the LLM)",
    {
      name: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .describe("Secret name (alphanumeric, hyphens, underscores)"),
      type: z.enum(["api_key", "oauth_token", "certificate"]).describe("Secret type"),
      project: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .optional()
        .describe("Project namespace"),
      injection: z
        .object({
          type: z.enum(["header", "query", "basic_auth", "bearer"]).describe("Injection method"),
          header_name: z.string().optional().describe("Header name (for type=header)"),
          query_param: z.string().optional().describe("Query parameter name (for type=query)"),
        })
        .optional()
        .describe("Default injection configuration"),
    },
    async (args) => {
      scopeGuard.checkAccess(PERMISSION, args.project);
      rateLimiter.checkLimit();

      // Create secret without a value — it will be in "pending" status
      // The value must be set separately via CLI: harpoc secret set <name>
      const result = await engine.createSecret({
        name: args.name,
        type: args.type as SecretType,
        project: args.project,
        injection: args.injection as InjectionConfig | undefined,
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                handle: result.handle,
                status: result.status,
                message:
                  result.status === "pending"
                    ? `Secret created. Set the value with: harpoc secret set ${args.name}`
                    : result.message,
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
