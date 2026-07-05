import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import { collectValueFromTty } from "../elicitation/tty-prompt.js";
import { collectValueViaUrlElicitation } from "../elicitation/value-collector.js";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "rotate";

export function registerRotateSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  enableTtyPrompt = false,
): void {
  server.tool(
    "rotate_secret",
    "Rotate a secret's value. The new value is collected out-of-band — via a one-time browser form (URL-mode elicitation) when the client supports it, otherwise set separately via CLI. Secret values never pass through the LLM.",
    {
      handle: z.string().describe("Secret handle to rotate"),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);
      rateLimiter.checkLimit();

      // The new value is collected out-of-band, per the thesis's channel
      // priority: URL-mode elicitation > controlling-terminal prompt >
      // deferred (CLI: harpoc secret rotate).
      let channel = "URL-mode elicitation";
      let value = await collectValueViaUrlElicitation(server, {
        subject: parsed.name,
        operation: "rotate",
      });
      if (value === null && enableTtyPrompt) {
        channel = "a terminal prompt";
        value = await collectValueFromTty({ subject: parsed.name, operation: "rotate" });
      }

      if (value) {
        try {
          await engine.rotateSecret(args.handle, value);
        } finally {
          value.fill(0);
        }
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  handle: args.handle,
                  status: "rotated",
                  message: `Secret rotated. The new value was collected via ${channel}, out-of-band of the model context.`,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

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
