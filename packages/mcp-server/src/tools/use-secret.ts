import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import { sanitizeUseSecretResult } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle, useSecretActionSchema } from "@harpoc/shared";
import { InjectionGuard } from "../guards/injection-guard.js";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";

const PERMISSION: Permission = "use";

export function registerUseSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  injectionGuard: InjectionGuard,
): void {
  server.tool(
    "use_secret",
    "Use a secret via a context-specific action — an HTTP request, a process execution, a proxied MCP tool call, a database query, a Git operation, or an SSH command. The secret value is injected at the execution layer and never exposed.",
    {
      handle: z.string().describe("Secret handle (secret://name)"),
      action: useSecretActionSchema.describe(
        "Action specification. HTTP: {type:'http', method, url, injection, headers?, body?, follow_redirects?, response_mode?}. Process: {type:'process', command, args?, env_var, working_directory?}. MCP: {type:'mcp', server, tool, arguments?}. Database: {type:'database', engine:'postgresql'|'mysql', host, database, query, params?}. Git: {type:'git', operation:'clone'|'pull'|'push', repository, args?, working_directory?}. SSH: {type:'ssh', host, user, command}. HTTP response_mode ('full'|'filtered'|'status_only') may only equal or tighten the secret's policy mode; 'status_only' returns the status code without a body. Target allowlists, the response-mode policy, TLS/host-key pinning and downstream config are set out-of-band via the trusted admin path (CLI/REST), never here.",
      ),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);

      const secretId = await engine.resolveSecretId(args.handle);
      rateLimiter.checkLimit(secretId, true);

      const response = await engine.useSecret(args.handle, args.action, scopeGuard.caller);

      // Defense-in-depth response sanitization (pattern-based, atop engine redaction)
      sanitizeUseSecretResult(response, injectionGuard);

      return {
        content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
      };
    },
  );
}
