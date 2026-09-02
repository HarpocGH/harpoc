import type {
  AccessPolicy,
  AccessPolicyInput,
  Agent,
  AgentPolicy,
  AgentStatusFilter,
  CertificateImportRequestInput,
  CertificateStatus,
  ConnectionConfig,
  CreateSecretRequest,
  CreateSecretResponse,
  GenerateCsrRequest,
  HealthResponse,
  InjectionPolicy,
  IssuedToken,
  IssuedTokenStatusFilter,
  McpServerConfig,
  OAuthFlowResult,
  OAuthTokenStatus,
  RegisterAgentInput,
  SetAgentPermissionsInput,
  SetAgentPermissionsResult,
  SetInjectionPolicyOptions,
  StartOAuthFlowInput,
  UpdateAgentInput,
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

/** Wire shapes for the v1.4 agent governance inputs — re-exported for callers. */
export type {
  RegisterAgentInput,
  UpdateAgentInput,
  SetAgentPermissionsInput,
} from "@harpoc/shared";

/** Filters for {@link VaultClient.listTokens} (the issued-token registry, v1.4). */
export interface ListTokensOptions {
  agent?: string;
  status?: IssuedTokenStatusFilter;
}

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
    policy: InjectionPolicy,
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
  registerAgent(input: RegisterAgentInput): Promise<Agent>;
  listAgents(status?: AgentStatusFilter): Promise<Agent[]>;
  getAgent(name: string): Promise<Agent>;
  updateAgent(name: string, input: UpdateAgentInput): Promise<Agent>;
  deactivateAgent(name: string): Promise<{ revoked_tokens: number }>;
  activateAgent(name: string): Promise<Agent>;
  deleteAgent(name: string): Promise<{ revoked_tokens: number; removed_grants: number }>;
  listAgentPolicies(name: string): Promise<AgentPolicy[]>;
  setAgentPermissions(
    name: string,
    handle: string,
    input: SetAgentPermissionsInput,
  ): Promise<SetAgentPermissionsResult>;
  listTokens(options?: ListTokensOptions): Promise<IssuedToken[]>;
  revokeToken(jti: string): Promise<void>;
  getHealth(): Promise<HealthResponse>;
  startOAuthFlow(input: StartOAuthFlowInput): Promise<OAuthFlowResult>;
  getOAuthStatus(handle: string): Promise<OAuthTokenStatus>;
  refreshOAuthToken(handle: string): Promise<number | null>;
  importCertificate(
    name: string,
    input: Omit<CertificateImportRequestInput, "name">,
  ): Promise<CertificateRef>;
  generateCsr(name: string, input: Omit<GenerateCsrRequest, "name">): Promise<GeneratedCsrRef>;
  renewCertificate(handle: string): Promise<CertificateStatus>;
  getCertificateStatus(handle: string): Promise<CertificateStatus>;
}
