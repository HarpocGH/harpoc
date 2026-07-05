import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { Permission, UseSecretAction, UseSecretResponse } from "@harpoc/shared";
import { parseHandle, useSecretActionSchema } from "@harpoc/shared";
import { InjectionGuard } from "../guards/injection-guard.js";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "use";

/** Sanitize a use_secret result across both injection mechanisms. */
function sanitizeResult(result: UseSecretResponse, guard: InjectionGuard): void {
  if (result.type === "http") {
    if (result.body) result.body = guard.sanitize(result.body);
    if (result.headers) {
      for (const [key, value] of Object.entries(result.headers)) {
        result.headers[key] = guard.sanitize(value);
      }
    }
    if (result.error) result.error = guard.sanitize(result.error);
  } else {
    result.stdout = guard.sanitize(result.stdout);
    result.stderr = guard.sanitize(result.stderr);
    if (result.error) result.error = guard.sanitize(result.error);
  }
}

export function registerUseSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  injectionGuard: InjectionGuard,
): void {
  server.tool(
    "use_secret",
    "Use a secret via a context-specific action — an HTTP request or a process execution. The secret value is injected at the execution layer and never exposed.",
    {
      handle: z.string().describe("Secret handle (secret://name)"),
      action: useSecretActionSchema.describe(
        "Action specification. HTTP: {type:'http', method, url, injection, headers?, body?, follow_redirects?}. Process: {type:'process', command, args?, env_var, working_directory?}.",
      ),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);

      const secretId = await engine.resolveSecretId(args.handle);
      rateLimiter.checkLimit(secretId, true);

      const response = await engine.useSecret(args.handle, args.action as UseSecretAction);

      // Defense-in-depth response sanitization (pattern-based, atop engine redaction)
      sanitizeResult(response, injectionGuard);

      return {
        content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
      };
    },
  );
}
