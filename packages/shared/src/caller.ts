import type { CallerContext, VaultApiToken } from "./types.js";
import { TokenPrincipalType } from "./types.js";

/**
 * Map a verified token to the engine's caller identity — the single
 * construction point used by every interface layer (REST, MCP). A token
 * without a `principal_type` claim is an agent principal (the pre-claim
 * default, covering all previously issued tokens); the `project` claim rides
 * along so the engine can derive the (project, <claim>) principal.
 */
export function callerFromToken(token: VaultApiToken): CallerContext {
  const caller: CallerContext = {
    principal_type: token.principal_type ?? TokenPrincipalType.AGENT,
    principal_id: token.sub,
  };
  if (token.project) {
    caller.project = token.project;
  }
  return caller;
}
