import type { Permission, VaultApiToken } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import { parseHandle } from "@harpoc/shared";

/**
 * Enforce 3-dimensional token scope (permission, project, secret names).
 * Mirrors ScopeGuard.checkAccess() from mcp-server.
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

  // 3. Secret name scope check
  if (token.secrets?.length && secretName !== undefined) {
    if (!token.secrets.includes(secretName)) {
      throw VaultError.accessDenied("Token does not grant access to this secret");
    }
  }
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
