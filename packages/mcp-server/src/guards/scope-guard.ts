import type {
  AccessInterface,
  AuditVisibilityScope,
  CallerContext,
  Permission,
  ScopeRefusalReason,
  VaultApiToken,
} from "@harpoc/shared";
import {
  auditScopeFromToken,
  callerFromToken,
  matchesSecretNameScope,
  TOKENLESS_STDIO_PRINCIPAL,
  tokenlessStdioCaller,
  VaultError,
} from "@harpoc/shared";

/**
 * 3-dimensional launch-token scope enforcement:
 * 1. Permission — token's scope must include the required permission (or admin)
 * 2. Project — if token specifies a project, only that project's secrets are accessible
 * 3. Secrets — if token specifies secret-name patterns (`*` wildcards, thesis
 *    §4.7), only secrets with matching names are accessible
 *
 * The interface tag ("mcp" for stdio, "mcp-http" for Streamable HTTP) rides on
 * the derived caller for audit attribution only — never scope enforcement.
 */
export class ScopeGuard {
  constructor(
    private readonly token: VaultApiToken | null,
    private readonly accessInterface: AccessInterface = "mcp",
    /**
     * Revocation lookup, consulted on every check. The stdio transport verifies
     * its launch token once at construction, so without this a revoked token
     * kept its full scope for the life of the server (H7). The HTTP transport
     * re-verifies per request anyway, where this is a redundant second line.
     */
    private readonly isRevoked?: (jti: string) => boolean,
    /** Socket peer of the session's connection — Streamable HTTP only (E75i). */
    private readonly remoteAddress?: string,
    /**
     * Invoked once, immediately before a scope refusal throws, with the operation
     * the caller named and the branch that refused — the server factory binds it
     * to the engine's `access.denied` writer (D2g, 2026-09-23). Expiry and
     * revocation are not scope refusals and never reach it.
     */
    private readonly onRefusal?: (operation: string, reason: ScopeRefusalReason) => void,
  ) {}

  /**
   * Check whether the current token grants access for the given operation.
   * Throws VaultError(ACCESS_DENIED) if access is not permitted.
   */
  checkAccess(
    permission: Permission,
    project?: string,
    secretName?: string,
    operation?: string,
  ): void {
    // Null token = full access (no launch token provided)
    if (!this.token) return;

    // 0. Token expiry recheck (long-running MCP server may outlive token TTL)
    if (this.token.exp <= Math.floor(Date.now() / 1000)) {
      throw VaultError.tokenExpired();
    }

    // 0b. Revocation recheck — the launch token was verified once, at
    // construction, and revocation must take effect on the running server.
    if (this.isRevoked?.(this.token.jti) === true) {
      throw VaultError.tokenRevoked();
    }

    // 1. Permission check
    if (!this.token.scope.includes(permission) && !this.token.scope.includes("admin")) {
      this.refuse(operation, "permission", `Token lacks permission: ${permission}`);
    }

    // 2. Project scope check
    if (this.token.project && project !== undefined && project !== this.token.project) {
      this.refuse(operation, "project", `Token is scoped to project: ${this.token.project}`);
    }
    // Deny individual access to global (project-less) secrets for project-scoped tokens
    if (this.token.project && secretName !== undefined && project === undefined) {
      this.refuse(operation, "project", `Token is scoped to project: ${this.token.project}`);
    }

    // 3. Secret name scope check (name patterns, thesis §4.7)
    if (secretName !== undefined && !matchesSecretNameScope(secretName, this.token.secrets)) {
      this.refuse(operation, "secret", "Token does not grant access to this secret");
    }
  }

  private refuse(
    operation: string | undefined,
    reason: ScopeRefusalReason,
    message: string,
  ): never {
    this.onRefusal?.(operation ?? "unnamed", reason);
    throw VaultError.accessDenied(message);
  }

  /**
   * Filter a list of secrets by the token's project and secret-name scope.
   * Returns only secrets the token is allowed to see.
   */
  filterByScope<T extends { name: string; project: string | null }>(secrets: T[]): T[] {
    if (!this.token) return secrets;

    let filtered = secrets;
    if (this.token.project) {
      filtered = filtered.filter((s) => s.project === this.token?.project);
    }
    if (this.token.secrets?.length) {
      filtered = filtered.filter((s) => matchesSecretNameScope(s.name, this.token?.secrets));
    }
    return filtered;
  }

  /**
   * The identity a value-collection round is sealed to: the token's jti —
   * never a name an operator can register — or the tokenless stdio caller.
   */
  get principalBinding(): string {
    return this.token?.jti ?? TOKENLESS_STDIO_PRINCIPAL;
  }

  /**
   * Caller identity for engine-level policy enforcement and audit attribution
   * (thesis §4.6, §4.3.4): the token's, stamped with this transport and — on
   * Streamable HTTP — the socket peer (E75i); without a token, the synthetic
   * `tokenless-stdio` caller (R4/E78b): attribution-only and exempt like an
   * admin-scoped user token, so an unrestricted server's rows name it instead
   * of blending into the CLI's NULL-principal rows.
   */
  get caller(): CallerContext {
    return this.token
      ? callerFromToken(this.token, this.accessInterface, this.remoteAddress)
      : tokenlessStdioCaller(this.accessInterface);
  }

  /**
   * The token's project / secret-name dimensions for surfaces that return rows
   * about secrets other than the one addressed — the audit resource, which
   * enforced the permission dimension alone (L10). Undefined without a token
   * (trusted local mode) and for a token unrestricted in both dimensions.
   */
  get auditScope(): AuditVisibilityScope | undefined {
    return this.token ? auditScopeFromToken(this.token) : undefined;
  }
}
