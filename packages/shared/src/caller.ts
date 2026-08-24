import type {
  AccessInterface,
  AuditVisibilityScope,
  CallerContext,
  Permission,
  VaultApiToken,
} from "./types.js";
import { TokenPrincipalType } from "./types.js";
import { VaultError } from "./errors.js";
import { matchesSecretNameScope } from "./name-pattern.js";

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
  if (token.scope.includes("admin")) {
    caller.admin_scope = true;
  }
  return caller;
}

/**
 * R7 (v1.4.1): the one caller class exempt from per-secret access policies —
 * a user-type principal whose token carried admin scope. The flag exists only
 * on callerFromToken-built contexts, so hand-built callers are never exempt.
 */
export function isAdminUserCaller(caller: CallerContext): boolean {
  return caller.principal_type === TokenPrincipalType.USER && caller.admin_scope === true;
}

/**
 * Enforce 3-dimensional token scope (permission, project, secret-name
 * patterns — `*` wildcards, thesis §4.7). The single scope predicate shared by
 * every token-bearing interface that checks scope outside a ScopeGuard: the
 * REST middleware and the CLI token path both call it (relocated here from
 * rest-api so the CLI can enforce identical semantics without a Hono
 * dependency — the `applyTokenEndpointAuth` precedent). Mirrors
 * ScopeGuard.checkAccess() from mcp-server, which adds the per-call
 * revocation recheck the long-lived MCP transports need.
 */
export function checkTokenScope(
  token: VaultApiToken,
  permission: Permission,
  project?: string,
  secretName?: string,
): void {
  // 1. Permission check
  if (!token.scope.includes(permission) && !token.scope.includes("admin")) {
    throw VaultError.accessDenied(`Token lacks permission: ${permission}`);
  }

  // 2. Project scope check
  if (token.project && project !== undefined && project !== token.project) {
    throw VaultError.accessDenied(`Token is scoped to project: ${token.project}`);
  }
  // Deny individual access to global (project-less) secrets for project-scoped tokens
  if (token.project && secretName !== undefined && project === undefined) {
    throw VaultError.accessDenied(`Token is scoped to project: ${token.project}`);
  }

  // 3. Secret name scope check (name patterns, thesis §4.7)
  if (secretName !== undefined && !matchesSecretNameScope(secretName, token.secrets)) {
    throw VaultError.accessDenied("Token does not grant access to this secret");
  }
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
