import type { McpServer } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";
import { REVOKE_SECRET_TOOL } from "./definitions.js";

const PERMISSION: Permission = "revoke";

export function registerRevokeSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.registerTool(REVOKE_SECRET_TOOL.name, REVOKE_SECRET_TOOL.config, async (args) => {
    const parsed = parseHandle(args.handle);
    scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name, "revoke_secret");
    rateLimiter.checkLimit();

    await engine.revokeSecret(args.handle, scopeGuard.caller);

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              handle: args.handle,
              status: "revoked",
              message: "Secret has been permanently revoked",
            },
            null,
            2,
          ),
        },
      ],
    };
  });
}
