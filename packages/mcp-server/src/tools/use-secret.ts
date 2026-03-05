import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEngine } from "@harpoc/core";
import type { FollowRedirects, HttpMethod, InjectionConfig, Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
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
    "Execute an HTTP request with a secret injected (the secret value is never exposed)",
    {
      handle: z.string().describe("Secret handle"),
      request: z
        .object({
          method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).describe("HTTP method"),
          url: z.string().url().describe("Target URL (HTTPS required)"),
          headers: z.record(z.string()).optional().describe("Additional HTTP headers"),
          body: z.string().optional().describe("Request body"),
          timeout_ms: z
            .number()
            .int()
            .positive()
            .max(300_000)
            .optional()
            .describe("Timeout in milliseconds"),
        })
        .describe("HTTP request configuration"),
      injection: z
        .object({
          type: z
            .enum(["header", "query", "basic_auth", "bearer"])
            .describe("How to inject the secret"),
          header_name: z.string().optional().describe("Header name (for type=header)"),
          query_param: z.string().optional().describe("Query parameter name (for type=query)"),
        })
        .describe("Secret injection method"),
      follow_redirects: z
        .enum(["same-origin", "none", "any"])
        .optional()
        .describe("Redirect policy"),
    },
    async (args) => {
      const parsed = parseHandle(args.handle);
      scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name);

      const secretId = await engine.resolveSecretId(args.handle);
      rateLimiter.checkLimit(secretId, true);

      const response = await engine.useSecret(
        args.handle,
        {
          method: args.request.method as HttpMethod,
          url: args.request.url,
          headers: args.request.headers,
          body: args.request.body,
          timeoutMs: args.request.timeout_ms,
        },
        args.injection as InjectionConfig,
        args.follow_redirects as FollowRedirects | undefined,
      );

      // Sanitize response to prevent credential leakage
      if (response.body) {
        response.body = injectionGuard.sanitize(response.body);
      }
      if (response.headers) {
        for (const [key, value] of Object.entries(response.headers)) {
          response.headers[key] = injectionGuard.sanitize(value);
        }
      }
      if (response.error) {
        response.error = injectionGuard.sanitize(response.error);
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
      };
    },
  );
}
