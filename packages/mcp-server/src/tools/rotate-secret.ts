import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import { collectValueFromTty } from "../elicitation/tty-prompt.js";
import type { ValueRequestState } from "../elicitation/request-state.js";
import {
  collectValueViaUrlElicitation,
  elicitValueViaInputRequired,
  isModernRequest,
  resumeValueCollection,
} from "../elicitation/value-collector.js";
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
  server.registerTool(
    "rotate_secret",
    {
      description:
        "Rotate a secret's value. The new value is collected out-of-band — via a one-time browser form (URL-mode elicitation) when the client supports it, otherwise set separately via CLI. Secret values never pass through the LLM.",
      inputSchema: z.object({
        handle: z.string().describe("Secret handle to rotate"),
      }),
    },
    async (args, ctx) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);
      // Bucketed per secret: like create_secret this opens a URL-mode value
      // collector per call, which the global tier alone barely bounds.
      rateLimiter.checkLimit(`rotate:${parsed.project ?? ""}/${parsed.name}`);

      const modern = isModernRequest(ctx);
      const finishRotate = async (value: Uint8Array | null, channel: string) => {
        if (value) {
          try {
            await engine.rotateSecret(args.handle, value, scopeGuard.caller);
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
      };

      // The new value is collected out-of-band, per the thesis's channel
      // priority: URL-mode elicitation > controlling-terminal prompt >
      // deferred (CLI: harpoc secret rotate).
      const collectOutOfBand = async (
        collected: Uint8Array | null,
      ): Promise<{ value: Uint8Array | null; channel: string }> => {
        let channel = "URL-mode elicitation";
        let value = collected;
        if (value === null && !modern) {
          value = await collectValueViaUrlElicitation(server, {
            subject: parsed.name,
            operation: "rotate",
          });
        }
        if (value === null && enableTtyPrompt) {
          channel = "a terminal prompt";
          value = await collectValueFromTty({ subject: parsed.name, operation: "rotate" });
        }
        return { value, channel };
      };

      if (modern) {
        const target = `${parsed.project ?? ""}/${parsed.name}`;
        const state = ctx.mcpReq.requestState<ValueRequestState>();
        if (state === undefined) {
          const pending = await elicitValueViaInputRequired(
            {
              subject: parsed.name,
              operation: "rotate",
              principal: scopeGuard.principalBinding,
              target,
            },
            ctx,
          );
          if (pending !== null) return pending;
        } else {
          const value = await resumeValueCollection(
            state,
            { principal: scopeGuard.principalBinding, operation: "rotate", target },
            ctx.mcpReq.inputResponses,
          );
          try {
            const collected = await collectOutOfBand(value);
            return await finishRotate(collected.value, collected.channel);
          } finally {
            value?.fill(0);
          }
        }
      }

      const collected = await collectOutOfBand(null);
      return finishRotate(collected.value, collected.channel);
    },
  );
}
