import type { AccessPolicy, CreateSecretResponse, UseSecretResponse } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditQueryOptions, DecryptedAuditEvent, SecretInfo } from "@harpoc/core";
import type {
  CreateSecretInput,
  GrantPolicyInput,
  HealthResponse,
  UseSecretInput,
  VaultClient,
} from "./client.js";

export interface RestClientOptions {
  baseUrl: string;
  token: string;
}

export class RestClient implements VaultClient {
  private readonly baseUrl: string;
  private readonly token: string;

  constructor(options: RestClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token;
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
      name: input.name,
      type: input.type,
      project: input.project,
      value: input.value ? Buffer.from(input.value).toString("base64") : undefined,
      injection: input.injection,
      expires_at: input.expiresAt,
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

  async useSecret(handle: string, input: UseSecretInput): Promise<UseSecretResponse> {
    return this.request<UseSecretResponse>(
      "POST",
      `/api/v1/secrets/${this.encodeHandle(handle)}/use`,
      {
        request: {
          method: input.request.method,
          url: input.request.url,
          headers: input.request.headers,
          body: input.request.body,
          timeout_ms: input.request.timeoutMs,
        },
        injection: input.injection,
        follow_redirects: input.followRedirects,
      },
    );
  }

  async grantPolicy(handle: string, input: GrantPolicyInput): Promise<AccessPolicy> {
    return this.request<AccessPolicy>(
      "POST",
      `/api/v1/secrets/${this.encodeHandle(handle)}/policies`,
      {
        principal_type: input.principalType,
        principal_id: input.principalId,
        permissions: input.permissions,
        expires_at: input.expiresAt,
      },
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

    const init: RequestInit = { method, headers };

    if (body !== undefined) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    const response = await fetch(url, init);

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
