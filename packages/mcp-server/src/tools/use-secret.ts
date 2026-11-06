import type { McpServer } from "@modelcontextprotocol/server";
import type { VaultEngine } from "@harpoc/core";
import { sanitizeUseSecretResult } from "@harpoc/core";
import type { Permission } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";
import { InjectionGuard } from "../guards/injection-guard.js";
import type { RateLimiter } from "../guards/rate-limiter.js";
import type { ScopeGuard } from "../guards/scope-guard.js";
import { USE_SECRET_TOOL } from "./definitions.js";

const PERMISSION: Permission = "use";

export function registerUseSecret(
  server: McpServer,
  engine: VaultEngine,
  scopeGuard: ScopeGuard,
  rateLimiter: RateLimiter,
  injectionGuard: InjectionGuard,
): void {
  server.registerTool(USE_SECRET_TOOL.name, USE_SECRET_TOOL.config, async (args) => {
    const parsed = parseHandle(args.handle);
    scopeGuard.checkAccess(PERMISSION, parsed.project, parsed.name, "use_secret");

    // Keyed on the handle, not a resolved id: resolving before the audited
    // engine path let an unknown-handle probe leave no row (N3).
    rateLimiter.checkLimit(`use:${parsed.project ?? ""}/${parsed.name}`, true);

    const response = await engine.useSecret(args.handle, args.action, scopeGuard.caller);

    // Defense-in-depth response sanitization (pattern-based, atop engine redaction)
    sanitizeUseSecretResult(response, injectionGuard);

    return {
      content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
    };
  });
}
