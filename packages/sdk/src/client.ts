import type {
  AccessPolicy,
  AccessPolicyInput,
  ConnectionConfig,
  CreateSecretRequest,
  CreateSecretResponse,
  HealthResponse,
  InjectionPolicy,
  InjectionPolicyInput,
  McpServerConfig,
  SetInjectionPolicyOptions,
  UseSecretAction,
  UseSecretResponse,
} from "@harpoc/shared";
import type { AuditQueryOptions, DecryptedAuditEvent, SecretInfo } from "@harpoc/core";

/**
 * The wire shape (createSecretInputSchema), with the binary value as bytes —
 * the REST client base64-encodes it in transit.
 */
export type CreateSecretInput = Omit<CreateSecretRequest, "value"> & {
  value?: Uint8Array;
};

/** The wire shape (accessPolicyInputSchema). */
export type GrantPolicyInput = AccessPolicyInput;

export type { HealthResponse };

export interface VaultClient {
  listSecrets(project?: string): Promise<SecretInfo[]>;
  getSecretInfo(handle: string): Promise<SecretInfo>;
  getSecretValue(handle: string): Promise<Uint8Array>;
  createSecret(input: CreateSecretInput): Promise<CreateSecretResponse>;
  rotateSecret(handle: string, newValue: Uint8Array): Promise<void>;
  revokeSecret(handle: string): Promise<void>;
  useSecret(handle: string, action: UseSecretAction): Promise<UseSecretResponse>;
  setInjectionPolicy(
    handle: string,
    policy: InjectionPolicyInput,
    options?: SetInjectionPolicyOptions,
  ): Promise<void>;
  getInjectionPolicy(handle: string): Promise<InjectionPolicy>;
  setMcpServerConfig(handle: string, config: McpServerConfig): Promise<void>;
  getMcpServerConfig(handle: string): Promise<McpServerConfig | undefined>;
  setConnectionConfig(handle: string, config: ConnectionConfig): Promise<void>;
  getConnectionConfig(handle: string): Promise<ConnectionConfig | undefined>;
  deleteConnectionConfig(handle: string): Promise<boolean>;
  grantPolicy(handle: string, input: GrantPolicyInput): Promise<AccessPolicy>;
  revokePolicy(handle: string, policyId: string): Promise<void>;
  listPolicies(handle: string): Promise<AccessPolicy[]>;
  queryAudit(options?: AuditQueryOptions): Promise<DecryptedAuditEvent[]>;
  getHealth(): Promise<HealthResponse>;
}
