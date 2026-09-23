import type { Context } from "hono";
import { checkTokenScope, parseHandle } from "@harpoc/shared";
import type { Permission, ScopeRefusalReason } from "@harpoc/shared";
import { callerOf } from "../utils/caller.js";
import type { HarpocEnv } from "../types.js";

/**
 * Record a token-scope refusal on this request — one `access.denied` row naming
 * `<METHOD> <path>` (Hono's normalised path, percent-encoding kept, no query;
 * never `routePath`) under the requesting principal — before the route throws
 * (D2g, 2026-09-23).
 */
export function recordScopeRefusal(c: Context<HarpocEnv>, reason: ScopeRefusalReason): void {
  c.get("engine").auditScopeRefusal(callerOf(c), `${c.req.method} ${c.req.path}`, reason);
}

/**
 * The route-level scope check: `checkTokenScope` over the request's token, every
 * refusal recorded through `recordScopeRefusal` before it throws (D2g).
 */
export function checkScope(
  c: Context<HarpocEnv>,
  permission: Permission,
  project?: string,
  secretName?: string,
): void {
  checkTokenScope(c.get("token"), permission, project, secretName, (reason) =>
    recordScopeRefusal(c, reason),
  );
}

/**
 * Build a full secret handle URI from a route parameter.
 */
export function buildHandle(handle: string): string {
  return `secret://${handle}`;
}

/**
 * Extract project and name from a handle route parameter for scope checking.
 */
export function parseHandleParam(handle: string): { project?: string; name: string } {
  const parsed = parseHandle(`secret://${handle}`);
  return { project: parsed.project, name: parsed.name };
}
