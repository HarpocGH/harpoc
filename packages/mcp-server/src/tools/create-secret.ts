import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { injectionConfigSchema, secretTypeSchema } from "@harpoc/shared";
import { collectValueFromTty } from "../elicitation/tty-prompt.js";
import { collectValueViaUrlElicitation } from "../elicitation/value-collector.js";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "create";

export function registerCreateSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  enableTtyPrompt = false,
): void {
  server.tool(
    "create_secret",
    "Create a new secret. The value is collected out-of-band — via a one-time browser form (URL-mode elicitation) when the client supports it, otherwise set separately via CLI. Secret values never pass through the LLM.",
    {
      name: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .describe("Secret name (alphanumeric, hyphens, underscores)"),
      type: secretTypeSchema.describe("Secret type"),
      project: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .optional()
        .describe("Project namespace"),
      injection: injectionConfigSchema
        .optional()
        .describe(
          "Default injection configuration: {type:'bearer'|'basic_auth'} | {type:'header', header_name} | {type:'query', query_param}",
        ),
    },
    async (args) => {
      scopeGuard.checkAccess(PERMISSION, args.project, args.name);
      rateLimiter.checkLimit();

      // Create secret without a value — it starts in "pending" status. The
      // value is then collected out-of-band, per the thesis's channel
      // priority: URL-mode elicitation > controlling-terminal prompt >
      // deferred (CLI: harpoc secret set).
      const result = await engine.createSecret({
        name: args.name,
        type: args.type,
        project: args.project,
        injection: args.injection,
      });

      let status: string = result.status;
      let message =
        result.status === "pending"
          ? `Secret created. Set the value with: harpoc secret set ${args.name}`
          : result.message;

      if (result.status === "pending") {
        let channel = "URL-mode elicitation";
        let value = await collectValueViaUrlElicitation(server, {
          subject: args.name,
          operation: "create",
        });
        if (value === null && enableTtyPrompt) {
          channel = "a terminal prompt";
          value = await collectValueFromTty({ subject: args.name, operation: "create" });
        }
        if (value) {
          try {
            await engine.setSecretValue(result.handle, value);
          } finally {
            value.fill(0);
          }
          status = "created";
          message = `Secret created. The value was collected via ${channel}, out-of-band of the model context.`;
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ handle: result.handle, status, message }, null, 2),
          },
        ],
      };
    },
  );
}
