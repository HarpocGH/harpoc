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
 * One identity a caller acts under: the token subject under its issued
 * principal type, plus the derived project principal for project-scoped
 * tokens. Built once by the engine and shared by the point check and the
 * enumeration filter, so the two can never disagree about who a caller is.
 */
export interface PolicyPrincipal {
  type: PrincipalType;
  id: string;
}

/**
 * Manages access policies for secrets.
 *
 * Policies are enforced at the engine level (thesis §4.6): every credential
 * operation arriving with a token-derived caller checks the secret's stored
 * policy entries before proceeding, and so does every secret-scoped
 * configuration operation — reading a secret's injection policy, MCP-server
 * config, connection config or policy rows requires `read`, changing them
 * `rotate`, and granting or revoking a policy row itself `admin`. Otherwise a
 * principal denied `rotate` on a secret could still rewrite the allowlists
 * that bound where its credential may be injected.
 * Enumeration is governed too: every listing surface filters through
 * {@link filterPermitted} with the `list` permission, so a secret whose
 * `read` is denied cannot be recovered from a list, health summary or project
 * census — the same metadata row by another name.
 * Semantics are presence-gated restriction —
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
   * Batch form of {@link checkPermission} for enumeration (thesis §4.6
   * `list`): given the secret ids a caller would see under token scope alone,
   * return those its principals may act on under the same presence-gated
   * semantics — an id with no active policy row passes, an id with rows
   * passes only on a matching grant (or `admin`).
   *
   * One policy read for the whole page: a per-secret check would issue two
   * queries per row on every enumeration, and every enumeration surface
   * (list, health, projects) calls this.
   */
  filterPermitted(
    secretIds: readonly string[],
    principals: readonly PolicyPrincipal[],
    permission: Permission,
  ): Set<string> {
    const wanted = new Set(secretIds);
    const gated = new Set<string>();
    const granted = new Set<string>();
    const now = Date.now();

    for (const p of this.store.listPolicies()) {
      if (!wanted.has(p.secret_id)) continue;
      if (p.expires_at !== null && p.expires_at <= now) continue;

      gated.add(p.secret_id);

      if (
        !principals.some(
          (principal) => principal.type === p.principal_type && principal.id === p.principal_id,
        )
      ) {
        continue;
      }
      if (p.permissions.includes("admin" as Permission) || p.permissions.includes(permission)) {
        granted.add(p.secret_id);
      }
    }

    const permitted = new Set<string>();
    for (const id of wanted) {
      if (!gated.has(id) || granted.has(id)) permitted.add(id);
    }
    return permitted;
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
