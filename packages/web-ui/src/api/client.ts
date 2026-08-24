import type {
  AccessPolicy,
  Agent,
  AgentPolicy,
  AgentStatusFilter,
  AuditEventType,
  CertificateStatus,
  CreateSecretRequest,
  CreateSecretResponse,
  ExpiringCertificateInfo,
  ExpiringOAuthTokenInfo,
  HealthResponse,
  InjectionPolicy,
  InjectionPolicyInput,
  IssuedToken,
  IssuedTokenStatusFilter,
  OAuthTokenStatus,
  PrincipalType,
  RegisterAgentInput,
  SecretType,
  SetAgentPermissionsInput,
  SetAgentPermissionsResult,
  UpdateAgentInput,
} from "@harpoc/shared";

/** REST error envelope is flat: { error: <code>, message } (error-handler.ts). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * Secret metadata as the API serializes it — camelCase, exactly the object
 * core's `getSecretInfo`/`listSecrets` hand to `c.json`. The canonical
 * declaration lives in `@harpoc/core`, which this package deliberately does not
 * depend on (`@harpoc/shared` is its only workspace dependency, pinned by
 * scaffold.test.ts), so the wire contract is mirrored here.
 */
export interface SecretInfo {
  handle: string;
  name: string;
  type: SecretType;
  project: string | null;
  /** Effective status: the lazy-expiry projection, not necessarily the stored one. */
  status: string;
  version: number;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
  rotatedAt: number | null;
}

/** One row of `GET /audit` — core's `DecryptedAuditEvent` over the wire. */
export interface AuditEventWire {
  id: number;
  timestamp: number;
  event_type: AuditEventType;
  secret_id: string | null;
  principal_type: PrincipalType | null;
  principal_id: string | null;
  detail: Record<string, unknown> | null;
  /** Set when a stored detail blob could not be decrypted (legacy AAD, or tampered). */
  detail_unreadable?: boolean;
  ip_address: string | null;
  session_id: string | null;
  success: boolean;
}

/** `GET /health/expiring`: expiring secrets in `data`, the two aggregates as siblings. */
export interface ExpiringReport {
  expiring: SecretInfo[];
  oauth_refresh_needed: ExpiringOAuthTokenInfo[];
  certificates_nearing_renewal: ExpiringCertificateInfo[];
}

export interface AuditVerifyReport {
  valid: boolean;
  checked: number;
  legacy: number;
  first_broken_id: number | null;
}

export interface AuditQueryFilters {
  secret_id?: string;
  event_type?: AuditEventType;
  since?: number;
  until?: number;
  limit?: number;
  success?: boolean;
  principal_type?: PrincipalType;
  principal_id?: string;
}

/** `GET /tokens` filters — the issued-token registry's two query params. */
export interface TokenQueryFilters {
  status?: IssuedTokenStatusFilter;
  agent?: string;
}

/** `POST /oauth/:handle/refresh`: `engine.refreshOAuthToken`'s wire projection. */
export interface OAuthRefreshResult {
  refreshed: boolean;
  expires_at: number | null;
}

/** `DELETE /agents/:name`: what the cascade removed. */
export interface DeleteAgentResult {
  revoked_tokens: number;
  removed_grants: number;
}

/** PUT injection-policy body: the policy plus the per-operation interpreter waiver. */
export type SetInjectionPolicyRequest = InjectionPolicyInput & {
  acknowledge_interpreters?: boolean;
};

export interface ApiClient {
  health(): Promise<HealthResponse>;
  expiringReport(days?: number): Promise<ExpiringReport>;
  listSecrets(project?: string): Promise<SecretInfo[]>;
  getSecret(handle: string): Promise<SecretInfo>;
  createSecret(input: CreateSecretRequest): Promise<CreateSecretResponse>;
  /** `valueBase64` is the wire encoding the rotate route parses — base64, validated there. */
  rotateSecret(handle: string, valueBase64: string): Promise<void>;
  deleteSecret(handle: string): Promise<void>;
  getInjectionPolicy(handle: string): Promise<InjectionPolicy>;
  putInjectionPolicy(handle: string, policy: SetInjectionPolicyRequest): Promise<void>;
  getAccessPolicies(handle: string): Promise<AccessPolicy[]>;
  getOAuthStatus(handle: string): Promise<OAuthTokenStatus>;
  refreshOAuth(handle: string): Promise<OAuthRefreshResult>;
  getCertificateStatus(handle: string): Promise<CertificateStatus>;
  renewCertificate(handle: string): Promise<CertificateStatus>;
  queryAudit(filters: AuditQueryFilters): Promise<AuditEventWire[]>;
  verifyAuditChain(): Promise<AuditVerifyReport>;
  listAgents(status?: AgentStatusFilter): Promise<Agent[]>;
  getAgent(name: string): Promise<Agent>;
  registerAgent(input: RegisterAgentInput): Promise<Agent>;
  /** PUT is replace semantics: an omitted field is cleared, not kept. */
  updateAgent(name: string, input: UpdateAgentInput): Promise<Agent>;
  deactivateAgent(name: string): Promise<{ revoked_tokens: number }>;
  activateAgent(name: string): Promise<Agent>;
  deleteAgent(name: string): Promise<DeleteAgentResult>;
  listAgentPolicies(name: string): Promise<AgentPolicy[]>;
  setAgentPermissions(
    name: string,
    handle: string,
    input: SetAgentPermissionsInput,
  ): Promise<SetAgentPermissionsResult>;
  listTokens(filters?: TokenQueryFilters): Promise<IssuedToken[]>;
  revokeToken(jti: string): Promise<void>;
}

/**
 * A handle minus its scheme: `project/name` for a project-scoped secret, which
 * is the identity both the API's `:handle` param and the UI's own route segment
 * carry. The bare `name` is a different secret.
 */
export const secretPath = (handle: string): string =>
  handle.startsWith("secret://") ? handle.slice("secret://".length) : handle;

/**
 * A handle is one route segment: the scheme comes off and the project separator
 * is percent-encoded, which is how the API's own tests address a project-scoped
 * secret (`myproj%2Ftest-key`).
 */
const handlePath = (handle: string): string => encodeURIComponent(secretPath(handle));

/**
 * Query string from a filter object. An undefined value is an absent filter —
 * and so is an empty string: `principal_id=` is a 400 (the schema's minimum
 * length), and empty is exactly what a cleared input or a missing query param
 * reads as at every call site.
 */
function queryString(filters: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === "") continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs === "" ? "" : `?${qs}`;
}

/**
 * Session signals. `GET /health` is mounted ahead of `authMiddleware` on the
 * real API — it is unauthenticated and never 401s — so the shell cannot learn
 * from it that a token expired or was revoked, nor that the vault was sealed
 * under it. Every other call carries that news, and `call()` is the single seam
 * they all pass through, so the notification is raised here and the caller
 * still gets its `ApiError`.
 */
export function createApiClient(
  getAuthToken: () => string | null,
  fetchFn: typeof fetch = fetch,
  onUnauthorized?: () => void,
  onSealed?: () => void,
): ApiClient {
  async function call<T>(
    path: string,
    init?: RequestInit,
  ): Promise<{ data: T } & Record<string, unknown>> {
    const headers: Record<string, string> = {};
    const token = getAuthToken();
    if (token !== null) headers["Authorization"] = `Bearer ${token}`;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetchFn(path, { ...init, headers });
    const body = (await res.json().catch(() => null)) as
      | ({ data?: T; error?: string; message?: string } & Record<string, unknown>)
      | null;
    if (!res.ok) {
      // Keyed on the error code, not the 423: the status is shared with other
      // refusals, the code is not.
      if (res.status === 401) onUnauthorized?.();
      if (body?.error === "VAULT_LOCKED") onSealed?.();
      throw new ApiError(res.status, body?.error ?? "UNKNOWN", body?.message ?? res.statusText);
    }
    if (body === null) throw new ApiError(res.status, "UNKNOWN", "Empty response body");
    return body as { data: T } & Record<string, unknown>;
  }

  const get = async <T>(path: string): Promise<T> => (await call<T>(path)).data;
  const post = async <T>(path: string, body?: unknown): Promise<T> =>
    (
      await call<T>(path, {
        method: "POST",
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    ).data;
  const put = async <T>(path: string, body: unknown): Promise<T> =>
    (await call<T>(path, { method: "PUT", body: JSON.stringify(body) })).data;
  const del = async <T>(path: string): Promise<T> =>
    (await call<T>(path, { method: "DELETE" })).data;

  return {
    health: () => get<HealthResponse>("/api/v1/health"),
    expiringReport: async (days = 7) => {
      const body = await call<SecretInfo[]>(`/api/v1/health/expiring?days=${String(days)}`);
      return {
        expiring: body.data,
        oauth_refresh_needed: (body["oauth_refresh_needed"] ?? []) as ExpiringOAuthTokenInfo[],
        certificates_nearing_renewal: (body["certificates_nearing_renewal"] ??
          []) as ExpiringCertificateInfo[],
      };
    },
    listSecrets: (project) =>
      get<SecretInfo[]>(
        `/api/v1/secrets${project !== undefined ? `?project=${encodeURIComponent(project)}` : ""}`,
      ),
    getSecret: (handle) => get<SecretInfo>(`/api/v1/secrets/${handlePath(handle)}`),
    createSecret: (input) => post<CreateSecretResponse>("/api/v1/secrets", input),
    rotateSecret: async (handle, valueBase64) => {
      await call<unknown>(`/api/v1/secrets/${handlePath(handle)}/rotate`, {
        method: "POST",
        body: JSON.stringify({ value: valueBase64 }),
      });
    },
    // The revoke route refuses without `confirm=true`; the UI's own confirmation
    // dialog is what stands behind it.
    deleteSecret: async (handle) => {
      await call<unknown>(`/api/v1/secrets/${handlePath(handle)}?confirm=true`, {
        method: "DELETE",
      });
    },
    getInjectionPolicy: (handle) =>
      get<InjectionPolicy>(`/api/v1/secrets/${handlePath(handle)}/injection-policy`),
    putInjectionPolicy: async (handle, policy) => {
      await call<unknown>(`/api/v1/secrets/${handlePath(handle)}/injection-policy`, {
        method: "PUT",
        body: JSON.stringify(policy),
      });
    },
    getAccessPolicies: (handle) =>
      get<AccessPolicy[]>(`/api/v1/secrets/${handlePath(handle)}/policies`),
    getOAuthStatus: (handle) => get<OAuthTokenStatus>(`/api/v1/oauth/${handlePath(handle)}/status`),
    refreshOAuth: (handle) =>
      post<OAuthRefreshResult>(`/api/v1/oauth/${handlePath(handle)}/refresh`),
    getCertificateStatus: (handle) =>
      get<CertificateStatus>(`/api/v1/certificates/${handlePath(handle)}/status`),
    renewCertificate: (handle) =>
      post<CertificateStatus>(`/api/v1/certificates/${handlePath(handle)}/renew`, {}),
    // Spread, not passed straight through: an interface carries no implicit
    // index signature, so the anonymous copy is what `queryString` can read.
    queryAudit: (filters) => get<AuditEventWire[]>(`/api/v1/audit${queryString({ ...filters })}`),
    verifyAuditChain: () => post<AuditVerifyReport>("/api/v1/audit/verify"),

    listAgents: (status) => get<Agent[]>(`/api/v1/agents${queryString({ status })}`),
    getAgent: (name) => get<Agent>(`/api/v1/agents/${encodeURIComponent(name)}`),
    registerAgent: (input) => post<Agent>("/api/v1/agents", input),
    updateAgent: (name, input) => put<Agent>(`/api/v1/agents/${encodeURIComponent(name)}`, input),
    deactivateAgent: (name) =>
      post<{ revoked_tokens: number }>(`/api/v1/agents/${encodeURIComponent(name)}/deactivate`),
    activateAgent: (name) => post<Agent>(`/api/v1/agents/${encodeURIComponent(name)}/activate`),
    deleteAgent: (name) => del<DeleteAgentResult>(`/api/v1/agents/${encodeURIComponent(name)}`),
    listAgentPolicies: (name) =>
      get<AgentPolicy[]>(`/api/v1/agents/${encodeURIComponent(name)}/policies`),
    setAgentPermissions: (name, handle, input) =>
      put<SetAgentPermissionsResult>(
        `/api/v1/agents/${encodeURIComponent(name)}/secrets/${handlePath(handle)}/permissions`,
        input,
      ),
    // Built field by field rather than from the caller's object, so the query
    // string does not depend on the order the filters were written in.
    listTokens: (filters) =>
      get<IssuedToken[]>(
        `/api/v1/tokens${queryString({ status: filters?.status, agent: filters?.agent })}`,
      ),
    revokeToken: async (jti) => {
      await call<unknown>(`/api/v1/tokens/${encodeURIComponent(jti)}`, { method: "DELETE" });
    },
  };
}
