import type { AccessPolicy, Permission, PrincipalType } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { generateUUIDv7 } from "../crypto/random.js";
import type { SqliteStore } from "../storage/sqlite-store.js";

export interface GrantPolicyInput {
  secretId: string;
  principalType: PrincipalType;
  principalId: string;
  permissions: Permission[];
  expiresAt?: number;
  createdBy: string;
}

/**
 * Manages access policies for secrets.
 *
 * Policies are enforced at the engine level (thesis §4.6): every credential
 * operation arriving with a token-derived caller checks the secret's stored
 * policy entries before proceeding. Semantics are presence-gated restriction —
 * a secret with at least one active policy row requires the caller to hold a
 * matching grant; a secret with none is governed by token scope alone. The
 * trusted local path (CLI, in-process SDK — master-password/session
 * authenticated) carries no caller and is not subject to per-secret policies
 * (thesis §4.7 administration-versus-operation split).
 */
export class PolicyEngine {
  constructor(private readonly store: SqliteStore) {}

  grantPolicy(input: GrantPolicyInput): AccessPolicy {
    const policy: AccessPolicy = {
      id: generateUUIDv7(),
      secret_id: input.secretId,
      principal_type: input.principalType,
      principal_id: input.principalId,
      permissions: input.permissions,
      created_at: Date.now(),
      expires_at: input.expiresAt ?? null,
      created_by: input.createdBy,
    };

    this.store.insertPolicy(policy);
    return policy;
  }

  revokePolicy(policyId: string): void {
    const deleted = this.store.deletePolicy(policyId);
    if (!deleted) {
      throw new VaultError(ErrorCode.POLICY_NOT_FOUND, `Policy not found: ${policyId}`);
    }
  }

  listPolicies(secretId?: string): AccessPolicy[] {
    const policies = this.store.listPolicies(secretId);

    // Filter out expired policies
    const now = Date.now();
    return policies.filter((p) => p.expires_at === null || p.expires_at > now);
  }

  /**
   * Whether the secret has at least one active (non-expired) policy row —
   * the presence gate: only then do per-secret policies restrict
   * token-authenticated callers.
   */
  hasActivePolicies(secretId: string): boolean {
    return this.listPolicies(secretId).length > 0;
  }

  /**
   * Check if a principal has a specific permission on a secret.
   * Admin permission implies all other permissions.
   */
  checkPermission(
    secretId: string,
    principalType: PrincipalType,
    principalId: string,
    permission: Permission,
  ): boolean {
    const policies = this.store.listPoliciesByPrincipal(principalType, principalId);

    const now = Date.now();
    return policies.some((p) => {
      // Must match the secret
      if (p.secret_id !== secretId) return false;

      // Must not be expired
      if (p.expires_at !== null && p.expires_at <= now) return false;

      // Admin implies all permissions
      if (p.permissions.includes("admin" as Permission)) return true;

      return p.permissions.includes(permission);
    });
  }
}
