import type { McpServer } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";
import { GET_SECRET_INFO_TOOL } from "./definitions.js";

const PERMISSION: Permission = "read";

export function registerGetSecretInfo(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
): void {
  server.registerTool(GET_SECRET_INFO_TOOL.name, GET_SECRET_INFO_TOOL.config, async (args) => {
    const parsed = parseHandle(args.handle);
    scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name, "get_secret_info");
    rateLimiter.checkLimit();

    const info = await engine.getSecretInfo(args.handle, scopeGuard.caller);

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              handle: info.handle,
              name: info.name,
              type: info.type,
              project: info.project,
              status: info.status,
              version: info.version,
              created_at: info.createdAt,
              updated_at: info.updatedAt,
              expires_at: info.expiresAt,
              rotated_at: info.rotatedAt,
            },
            null,
            2,
          ),
        },
      ],
    };
  });
}
