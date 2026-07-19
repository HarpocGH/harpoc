import type { CallerContext, Permission, VaultApiToken } from "@harpoc/shared";
import { callerFromToken, matchesSecretNameScope, VaultError } from "@harpoc/shared";

/**
 * 3-dimensional launch-token scope enforcement:
 * 1. Permission — token's scope must include the required permission (or admin)
 * 2. Project — if token specifies a project, only that project's secrets are accessible
 * 3. Secrets — if token specifies secret-name patterns (`*` wildcards, thesis
 *    §4.7), only secrets with matching names are accessible
 */
export class ScopeGuard {
  constructor(private readonly token: VaultApiToken | null) {}

  /**
   * Check whether the current token grants access for the given operation.
   * Returns the principal ID (token subject) for audit logging.
   * Throws VaultError(ACCESS_DENIED) if access is not permitted.
   */
  checkAccess(permission: Permission, project?: string, secretName?: string): string {
    // Null token = full access (no launch token provided)
    if (!this.token) return "local";

    // 0. Token expiry recheck (long-running MCP server may outlive token TTL)
    if (this.token.exp <= Math.floor(Date.now() / 1000)) {
      throw VaultError.tokenExpired();
    }

    // 1. Permission check
    if (!this.token.scope.includes(permission) && !this.token.scope.includes("admin")) {
      throw VaultError.accessDenied(`Token lacks permission: ${permission}`);
    }

    // 2. Project scope check
    if (this.token.project && project !== undefined && project !== this.token.project) {
      throw VaultError.accessDenied(`Token is scoped to project: ${this.token.project}`);
    }
    // Deny individual access to global (project-less) secrets for project-scoped tokens
    if (this.token.project && secretName !== undefined && project === undefined) {
      throw VaultError.accessDenied(`Token is scoped to project: ${this.token.project}`);
    }

    // 3. Secret name scope check (name patterns, thesis §4.7)
    if (secretName !== undefined && !matchesSecretNameScope(secretName, this.token.secrets)) {
      throw VaultError.accessDenied("Token does not grant access to this secret");
    }

    return this.token.sub;
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

  /** Get the principal ID without performing access checks. */
  get principal(): string {
    return this.token?.sub ?? "local";
  }

  /**
   * Token-derived caller identity for engine-level policy enforcement
   * (thesis §4.6). Undefined without a token — the local full-access mode is
   * the trusted path and is not subject to per-secret policies.
   */
  get caller(): CallerContext | undefined {
    return this.token ? callerFromToken(this.token) : undefined;
  }
}
