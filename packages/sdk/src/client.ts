import type {
  AccessPolicy,
  AccessPolicyInput,
  CertificateImportRequestInput,
  CertificateStatus,
  ConnectionConfig,
  CreateSecretRequest,
  CreateSecretResponse,
  GenerateCsrRequest,
  HealthResponse,
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

/**
 * Declared here rather than imported from `@harpoc/cert-manager`: that package
 * is an optional peer (D4), and `client.ts` must stay loadable — and its
 * declarations emittable — without it installed.
 */
export interface CertificateRef {
  handle: string;
  secretId: string;
}

export interface GeneratedCsrRef {
  handle: string;
  csrPem: string;
}

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
  startOAuthFlow(input: StartOAuthFlowInput): Promise<OAuthFlowResult>;
  getOAuthStatus(handle: string): Promise<OAuthTokenStatus>;
  refreshOAuthToken(handle: string): Promise<number | null>;
  importCertificate(
    name: string,
    input: Omit<CertificateImportRequestInput, "name">,
  ): Promise<CertificateRef>;
  generateCsr(name: string, input: Omit<GenerateCsrRequest, "name">): Promise<GeneratedCsrRef>;
  renewCertificate(handle: string, options?: { httpPort?: number }): Promise<CertificateStatus>;
  getCertificateStatus(handle: string): Promise<CertificateStatus>;
}
