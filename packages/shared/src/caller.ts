import type {
  AccessInterface,
  AuditVisibilityScope,
  CallerContext,
  VaultApiToken,
} from "./types.js";
import { TokenPrincipalType } from "./types.js";

/**
 * Map a verified token to the engine's caller identity — the single
 * construction point used by every interface layer (REST, MCP). A token
 * without a `principal_type` claim is an agent principal (the pre-claim
 * default, covering all previously issued tokens); the `project` claim rides
 * along so the engine can derive the (project, <claim>) principal. The
 * optional `iface` tags which interface the request arrived through — audit
 * attribution only, never consulted by policy matching.
 */
export function callerFromToken(token: VaultApiToken, iface?: AccessInterface): CallerContext {
  const caller: CallerContext = {
    principal_type: token.principal_type ?? TokenPrincipalType.AGENT,
    principal_id: token.sub,
  };
  if (token.project) {
    caller.project = token.project;
  }
  if (iface) {
    caller.interface = iface;
  }
  return caller;
}

/**
 * The token's non-permission scope dimensions, for surfaces that return rows
 * about *other* secrets than the one addressed — today the audit log. The audit
 * surfaces checked the permission dimension only, so a project- or name-scoped
 * admin token read audit detail (handles, principals, config changes) for every
 * secret in the vault, with `?secret_id=` as a targeted oracle (L10).
 *
 * Returns undefined when the token is unrestricted in both dimensions — the
 * engine then does no filtering work at all.
 */
export function auditScopeFromToken(token: VaultApiToken): AuditVisibilityScope | undefined {
  const scope: AuditVisibilityScope = {};
  if (token.project) {
    scope.project = token.project;
  }
  if (token.secrets?.length) {
    scope.secrets = token.secrets;
  }
  return scope.project === undefined && scope.secrets === undefined ? undefined : scope;
}
