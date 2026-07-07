import type { VaultEngine } from "@harpoc/core";
import type {
  AccessPolicy,
  ConnectionConfig,
  CreateSecretResponse,
  InjectionPolicy,
  InjectionPolicyInput,
  McpServerConfig,
  SetInjectionPolicyOptions,
  UseSecretAction,
  UseSecretResponse,
} from "@harpoc/shared";
import type { AuditQueryOptions, DecryptedAuditEvent, SecretInfo } from "@harpoc/core";
import type {
  CreateSecretInput,
  GrantPolicyInput,
  HealthResponse,
  VaultClient,
} from "./client.js";
import { VAULT_VERSION } from "@harpoc/shared";

export class DirectClient implements VaultClient {
  constructor(private readonly engine: VaultEngine) {}

  async listSecrets(project?: string): Promise<SecretInfo[]> {
    return this.engine.listSecrets(project);
  }

  async getSecretInfo(handle: string): Promise<SecretInfo> {
    return this.engine.getSecretInfo(handle);
  }

  async getSecretValue(handle: string): Promise<Uint8Array> {
    return this.engine.getSecretValue(handle);
  }

  async createSecret(input: CreateSecretInput): Promise<CreateSecretResponse> {
    return this.engine.createSecret(input);
  }

  async rotateSecret(handle: string, newValue: Uint8Array): Promise<void> {
    return this.engine.rotateSecret(handle, newValue);
  }

  async revokeSecret(handle: string): Promise<void> {
    return this.engine.revokeSecret(handle);
  }

  async useSecret(handle: string, action: UseSecretAction): Promise<UseSecretResponse> {
    return this.engine.useSecret(handle, action);
  }

  async setInjectionPolicy(
    handle: string,
    policy: InjectionPolicyInput,
    options?: SetInjectionPolicyOptions,
  ): Promise<void> {
    return this.engine.setInjectionPolicy(handle, policy, options);
  }

  async getInjectionPolicy(handle: string): Promise<InjectionPolicy> {
    return this.engine.getInjectionPolicy(handle);
  }

  async setMcpServerConfig(handle: string, config: McpServerConfig): Promise<void> {
    return this.engine.setMcpServerConfig(handle, config);
  }

  async getMcpServerConfig(handle: string): Promise<McpServerConfig | undefined> {
    return this.engine.getMcpServerConfig(handle);
  }

  async setConnectionConfig(handle: string, config: ConnectionConfig): Promise<void> {
    return this.engine.setConnectionConfig(handle, config);
  }

  async getConnectionConfig(handle: string): Promise<ConnectionConfig | undefined> {
    return this.engine.getConnectionConfig(handle);
  }

  async deleteConnectionConfig(handle: string): Promise<boolean> {
    return this.engine.deleteConnectionConfig(handle);
  }

  async grantPolicy(handle: string, input: GrantPolicyInput): Promise<AccessPolicy> {
    const secretId = await this.engine.resolveSecretId(handle);
    return this.engine.grantPolicy(
      {
        secretId,
        principalType: input.principalType,
        principalId: input.principalId,
        permissions: input.permissions,
        expiresAt: input.expiresAt,
      },
      "sdk-direct",
    );
  }

  async revokePolicy(_handle: string, policyId: string): Promise<void> {
    this.engine.revokePolicy(policyId);
  }

  async listPolicies(handle: string): Promise<AccessPolicy[]> {
    const secretId = await this.engine.resolveSecretId(handle);
    return this.engine.listPolicies(secretId);
  }

  async queryAudit(options?: AuditQueryOptions): Promise<DecryptedAuditEvent[]> {
    return this.engine.queryAudit(options);
  }

  async getHealth(): Promise<HealthResponse> {
    return {
      state: this.engine.getState(),
      version: VAULT_VERSION,
    };
  }
}
