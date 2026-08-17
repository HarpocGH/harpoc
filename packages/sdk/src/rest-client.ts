import type {
  AccessPolicy,
  CertificateImportRequestInput,
  CertificateStatus,
  ConnectionConfig,
  CreateSecretResponse,
  GenerateCsrRequest,
  InjectionPolicy,
  InjectionPolicyInput,
  McpServerConfig,
  OAuthFlowResult,
  OAuthTokenStatus,
  SetInjectionPolicyOptions,
  StartOAuthFlowInput,
  UseSecretAction,
  UseSecretResponse,
} from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditQueryOptions, DecryptedAuditEvent, SecretInfo } from "@harpoc/core";
import type {
  CertificateRef,
  CreateSecretInput,
  GeneratedCsrRef,
  GrantPolicyInput,
  HealthResponse,
  VaultClient,
} from "./client.js";

export interface RestClientOptions {
  baseUrl: string;
  token: string;
  /** Per-request timeout in milliseconds (default 30 000). */
  timeoutMs?: number;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

export class RestClient implements VaultClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;

  constructor(options: RestClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  async listSecrets(project?: string): Promise<SecretInfo[]> {
    const params = project ? `?project=${encodeURIComponent(project)}` : "";
    return this.request<SecretInfo[]>("GET", `/api/v1/secrets${params}`);
  }

  async getSecretInfo(handle: string): Promise<SecretInfo> {
    return this.request<SecretInfo>("GET", `/api/v1/secrets/${this.encodeHandle(handle)}`);
  }

  async getSecretValue(handle: string): Promise<Uint8Array> {
    const result = await this.request<{ value: string }>(
      "GET",
      `/api/v1/secrets/${this.encodeHandle(handle)}/value`,
    );
    return new Uint8Array(Buffer.from(result.value, "base64"));
  }

  async createSecret(input: CreateSecretInput): Promise<CreateSecretResponse> {
    return this.request<CreateSecretResponse>("POST", "/api/v1/secrets", {
      ...input,
      value: input.value ? Buffer.from(input.value).toString("base64") : undefined,
    });
  }

  async rotateSecret(handle: string, newValue: Uint8Array): Promise<void> {
    await this.request<{ rotated: boolean }>(
      "POST",
      `/api/v1/secrets/${this.encodeHandle(handle)}/rotate`,
      { value: Buffer.from(newValue).toString("base64") },
    );
  }

  async revokeSecret(handle: string): Promise<void> {
    await this.request<{ revoked: boolean }>(
      "DELETE",
      `/api/v1/secrets/${this.encodeHandle(handle)}?confirm=true`,
    );
  }

  async useSecret(handle: string, action: UseSecretAction): Promise<UseSecretResponse> {
    return this.request<UseSecretResponse>(
      "POST",
      `/api/v1/secrets/${this.encodeHandle(handle)}/use`,
      { action },
    );
  }

  async setInjectionPolicy(
    handle: string,
    policy: InjectionPolicyInput,
    options?: SetInjectionPolicyOptions,
  ): Promise<void> {
    await this.request<{ updated: boolean }>(
      "PUT",
      `/api/v1/secrets/${this.encodeHandle(handle)}/injection-policy`,
      {
        url_allowlist: policy.url_allowlist,
        command_allowlist: policy.command_allowlist,
        env_allowlist: policy.env_allowlist,
        host_allowlist: policy.host_allowlist,
        response_mode: policy.response_mode,
        response_header_allowlist: policy.response_header_allowlist,
        network_isolation: policy.network_isolation,
        fs_isolation: policy.fs_isolation,
        acknowledge_interpreters: options?.acknowledge_interpreters ?? false,
      },
    );
  }

  async getInjectionPolicy(handle: string): Promise<InjectionPolicy> {
    return this.request<InjectionPolicy>(
      "GET",
      `/api/v1/secrets/${this.encodeHandle(handle)}/injection-policy`,
    );
  }

  async setMcpServerConfig(handle: string, config: McpServerConfig): Promise<void> {
    await this.request<{ updated: boolean }>(
      "PUT",
      `/api/v1/secrets/${this.encodeHandle(handle)}/mcp-server`,
      config,
    );
  }

  async getMcpServerConfig(handle: string): Promise<McpServerConfig | undefined> {
    const config = await this.request<McpServerConfig | null>(
      "GET",
      `/api/v1/secrets/${this.encodeHandle(handle)}/mcp-server`,
    );
    return config ?? undefined;
  }

  async setConnectionConfig(handle: string, config: ConnectionConfig): Promise<void> {
    await this.request<{ updated: boolean }>(
      "PUT",
      `/api/v1/secrets/${this.encodeHandle(handle)}/connection-config`,
      config,
    );
  }

  async getConnectionConfig(handle: string): Promise<ConnectionConfig | undefined> {
    const config = await this.request<ConnectionConfig | null>(
      "GET",
      `/api/v1/secrets/${this.encodeHandle(handle)}/connection-config`,
    );
    return config ?? undefined;
  }

  async deleteConnectionConfig(handle: string): Promise<boolean> {
    const result = await this.request<{ deleted: boolean }>(
      "DELETE",
      `/api/v1/secrets/${this.encodeHandle(handle)}/connection-config`,
    );
    return result.deleted;
  }

  async grantPolicy(handle: string, input: GrantPolicyInput): Promise<AccessPolicy> {
    return this.request<AccessPolicy>(
      "POST",
      `/api/v1/secrets/${this.encodeHandle(handle)}/policies`,
      input,
    );
  }

  async revokePolicy(handle: string, policyId: string): Promise<void> {
    await this.request<{ revoked: boolean }>(
      "DELETE",
      `/api/v1/secrets/${this.encodeHandle(handle)}/policies/${policyId}`,
    );
  }

  async listPolicies(handle: string): Promise<AccessPolicy[]> {
    return this.request<AccessPolicy[]>(
      "GET",
      `/api/v1/secrets/${this.encodeHandle(handle)}/policies`,
    );
  }

  async queryAudit(options?: AuditQueryOptions): Promise<DecryptedAuditEvent[]> {
    const params = new URLSearchParams();
    if (options?.secretId) params.set("secret_id", options.secretId);
    if (options?.eventType) params.set("event_type", options.eventType);
    if (options?.since !== undefined) params.set("since", String(options.since));
    if (options?.until !== undefined) params.set("until", String(options.until));
    if (options?.limit !== undefined) params.set("limit", String(options.limit));

    const qs = params.toString();
    return this.request<DecryptedAuditEvent[]>("GET", `/api/v1/audit${qs ? `?${qs}` : ""}`);
  }

  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/api/v1/health");
  }

  async startOAuthFlow(input: StartOAuthFlowInput): Promise<OAuthFlowResult> {
    return this.request<OAuthFlowResult>("POST", "/api/v1/oauth/authorize", input);
  }

  async getOAuthStatus(handle: string): Promise<OAuthTokenStatus> {
    return this.request<OAuthTokenStatus>(
      "GET",
      `/api/v1/oauth/${this.encodeHandle(handle)}/status`,
    );
  }

  async refreshOAuthToken(handle: string): Promise<number | null> {
    const result = await this.request<{ refreshed: boolean; expires_at: number | null }>(
      "POST",
      `/api/v1/oauth/${this.encodeHandle(handle)}/refresh`,
    );
    return result.expires_at;
  }

  async importCertificate(
    name: string,
    input: Omit<CertificateImportRequestInput, "name">,
  ): Promise<CertificateRef> {
    const result = await this.request<{ handle: string; secret_id: string }>(
      "POST",
      "/api/v1/certificates/import",
      { name, ...input },
    );
    return { handle: result.handle, secretId: result.secret_id };
  }

  async generateCsr(
    name: string,
    input: Omit<GenerateCsrRequest, "name">,
  ): Promise<GeneratedCsrRef> {
    const result = await this.request<{ handle: string; csr_pem: string }>(
      "POST",
      "/api/v1/certificates/csr",
      { name, ...input },
    );
    return { handle: result.handle, csrPem: result.csr_pem };
  }

  async renewCertificate(
    handle: string,
    options?: { httpPort?: number },
  ): Promise<CertificateStatus> {
    // The route parses a body unconditionally, so one is always sent — an
    // omitted port is simply absent from it (the ACME default applies).
    return this.request<CertificateStatus>(
      "POST",
      `/api/v1/certificates/${this.encodeHandle(handle)}/renew`,
      { http_port: options?.httpPort },
    );
  }

  async getCertificateStatus(handle: string): Promise<CertificateStatus> {
    return this.request<CertificateStatus>(
      "GET",
      `/api/v1/certificates/${this.encodeHandle(handle)}/status`,
    );
  }

  private encodeHandle(handle: string): string {
    // Strip secret:// prefix if present, then URL-encode
    const raw = handle.startsWith("secret://") ? handle.slice("secret://".length) : handle;
    return encodeURIComponent(raw);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.token}`,
    };

    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
    };

    if (body !== undefined) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    let response: Response;
    try {
      response = await fetch(url, init);
    } catch (err) {
      if (err instanceof Error && err.name === "TimeoutError") {
        throw new VaultError(
          ErrorCode.INTERNAL_ERROR,
          `Request timed out after ${this.timeoutMs}ms (${method} ${path})`,
        );
      }
      throw err;
    }

    let json: { data?: T; error?: string; message?: string };
    try {
      json = (await response.json()) as { data?: T; error?: string; message?: string };
    } catch {
      throw new VaultError(
        ErrorCode.INTERNAL_ERROR,
        `Server returned non-JSON response (HTTP ${response.status})`,
      );
    }

    if (!response.ok) {
      const code = (json.error ?? ErrorCode.INTERNAL_ERROR) as ErrorCode;
      const message = json.message ?? "Request failed";
      throw new VaultError(code, message);
    }

    return json.data as T;
  }
}
