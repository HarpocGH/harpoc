import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "rotate";

export function registerRotateSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.tool(
    "rotate_secret",
    "Rotate a secret's value (new value must be set via CLI for security — never pass secret values through the LLM)",
    {
      handle: z.string().describe("Secret handle to rotate"),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);
      rateLimiter.checkLimit();

      // We cannot call engine.rotateSecret() because it requires a value.
      // In stdio MCP transport, we have no secure channel to collect the value.
      // Return a deferred message — user must set the new value via CLI.
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                handle: args.handle,
                status: "pending_rotation",
                message: `Set new value with: harpoc secret rotate ${parsed.name}`,
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
