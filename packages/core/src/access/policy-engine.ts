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
 * config, connection config or policy rows requires `read`; changing the
 * MCP-server or connection config requires `rotate` (they pin endpoints);
 * changing the injection policy requires `admin` (it widens where the
 * credential may go — the same authority as granting a row; R1, 2026-09-01);
 * granting or revoking a policy row itself requires `admin`.
 * Enumeration is governed too: every listing surface filters through
 * {@link filterPermitted} with the `list` permission, so a secret whose
 * `read` is denied cannot be recovered from a list, health summary or project
 * census — the same metadata row by another name.
 * Semantics are explicit-grant (R1, 2026-09-01): a token-derived caller acts
 * on a secret only through a matching, unexpired row — a secret with no rows
 * is reachable by no such caller. The trusted local path (CLI, in-process
 * SDK — master-password/session authenticated) carries no caller and is not
 * subject to per-secret policies (thesis §4.7 administration-versus-operation
 * split); the admin-scoped user-type exemption (R7) is decided in the engine,
 * not here.
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
   * Whether the secret has at least one active (non-expired) policy row.
   * Reporting only since R1 (2026-09-01): `setAgentPermissions` reads it for
   * `gated_before`/`gated_after` — "does any principal hold an active row here" — and no
   * enforcement path consults it.
   */
  hasActivePolicies(secretId: string): boolean {
    return this.listPolicies(secretId).length > 0;
  }

  /**
   * Batch form of {@link checkPermission} for enumeration (thesis §4.6
   * `list`): given the secret ids a caller would see under token scope alone,
   * return those its principals hold a matching, unexpired grant on (or
   * `admin`). Explicit-grant (R1, 2026-09-01): an id with no row for the
   * caller is dropped, whatever other principals hold on it.
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
    const permitted = new Set<string>();
    const now = Date.now();

    for (const p of this.store.listPolicies()) {
      if (!wanted.has(p.secret_id)) continue;
      if (p.expires_at !== null && p.expires_at <= now) continue;
      if (
        !principals.some(
          (principal) => principal.type === p.principal_type && principal.id === p.principal_id,
        )
      ) {
        continue;
      }
      if (p.permissions.includes("admin" as Permission) || p.permissions.includes(permission)) {
        permitted.add(p.secret_id);
      }
    }
    return permitted;
  }

  /**
   * The union of permissions the caller's principals hold on one secret,
   * expired rows excluded and `admin` kept as the literal it is. The single
   * derivation behind {@link checkPermission} and the engine's point check,
   * which also needs "does the caller hold `read` or `list`" for the R5
   * existence-oracle mapping.
   */
  grantedPermissions(secretId: string, principals: readonly PolicyPrincipal[]): Set<Permission> {
    const held = new Set<Permission>();
    const now = Date.now();
    for (const principal of principals) {
      for (const p of this.store.listPoliciesByPrincipal(principal.type, principal.id)) {
        if (p.secret_id !== secretId) continue;
        if (p.expires_at !== null && p.expires_at <= now) continue;
        for (const permission of p.permissions) held.add(permission);
      }
    }
    return held;
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
    const held = this.grantedPermissions(secretId, [{ type: principalType, id: principalId }]);
    return held.has("admin" as Permission) || held.has(permission);
  }
}
