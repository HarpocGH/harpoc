import type { VaultEngine } from "@harpoc/core";
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
import type { AuditQueryOptions, DecryptedAuditEvent, SecretInfo } from "@harpoc/core";
import type {
  CertificateRef,
  CreateSecretInput,
  GeneratedCsrRef,
  GrantPolicyInput,
  HealthResponse,
  VaultClient,
} from "./client.js";
import {
  ENCRYPTED_KEY_IMPORT_REFUSAL,
  ErrorCode,
  VAULT_VERSION,
  VaultError,
  certificateImportSchema,
  generateCsrRequestSchema,
  isEncryptedPrivateKeyPem,
} from "@harpoc/shared";

/**
 * The optional OAuth/certificate peers (D4) reach this file as types only —
 * both aliases erase, so nothing here makes them a load-time dependency.
 */
type OAuthManagerT = import("@harpoc/oauth-proxy").OAuthManager;
type CertManagerT = import("@harpoc/cert-manager").CertManager;

export interface DirectClientOptions {
  oauthManager?: OAuthManagerT;
  certManager?: CertManagerT;
  /**
   * Receives OAuth background-flow failures (the deferred browser leg's
   * exchange, a device-code poll, an abort from {@link DirectClient.close}).
   * Default: a stderr warning, mirroring the REST and MCP hosts — a silent
   * default left direct-mode failures invisible until polled.
   */
  onBackgroundFlowError?: (secretId: string, err: unknown) => void;
}

/**
 * In-process VaultClient over a constructed VaultEngine — the trusted local
 * path (thesis §4.7): calls carry no token-derived caller, so per-secret
 * access policies do not apply (unlike RestClient, whose server enforces
 * them). Embedders exposing DirectClient to untrusted principals must gate
 * access themselves.
 */
export class DirectClient implements VaultClient {
  private oauthManagerInstance?: OAuthManagerT;
  private certManagerInstance?: CertManagerT;
  private readonly onBackgroundFlowError?: (secretId: string, err: unknown) => void;

  constructor(
    private readonly engine: VaultEngine,
    options?: DirectClientOptions,
  ) {
    this.oauthManagerInstance = options?.oauthManager;
    this.certManagerInstance = options?.certManager;
    this.onBackgroundFlowError = options?.onBackgroundFlowError;
  }

  /**
   * Abort any pending background OAuth flows (auth-code callback waits,
   * device-code polls): the callback server otherwise pins the event loop
   * for the callback timeout, and an orphaned poll would complete against
   * an engine the embedder has already destroyed. Idempotent; a client that
   * never touched OAuth has nothing to cancel.
   */
  close(): void {
    this.oauthManagerInstance?.cancelPendingFlows();
  }

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
    return this.engine.createSecret({
      name: input.name,
      type: input.type,
      project: input.project,
      value: input.value,
      expiresAt: input.expires_at,
    });
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
        principalType: input.principal_type,
        principalId: input.principal_id,
        permissions: input.permissions,
        expiresAt: input.expires_at,
      },
      "sdk-direct",
    );
  }

  async revokePolicy(handle: string, policyId: string): Promise<void> {
    // Verify the policy belongs to this secret (cross-secret IDOR guard) —
    // REST-path parity: the two client modes must enforce the same contract.
    const secretId = await this.engine.resolveSecretId(handle);
    const policies = this.engine.listPolicies(secretId);
    if (!policies.some((p) => p.id === policyId)) {
      throw new VaultError(ErrorCode.POLICY_NOT_FOUND, "Policy not found for this secret");
    }
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

  async startOAuthFlow(input: StartOAuthFlowInput): Promise<OAuthFlowResult> {
    // The grant dispatch and its wire-safe projections (never secretId, never
    // a completion promise — D2) live in oauth-proxy, shared with REST.
    const { startOAuthFlowResult } = await import("@harpoc/oauth-proxy");
    const manager = await this.loadOAuthManager();
    return startOAuthFlowResult(manager, input);
  }

  async getOAuthStatus(handle: string): Promise<OAuthTokenStatus> {
    const secretId = await this.engine.resolveSecretId(handle);
    return this.engine.getOAuthTokenStatus(secretId);
  }

  async refreshOAuthToken(handle: string): Promise<number | null> {
    const secretId = await this.engine.resolveSecretId(handle);
    return this.engine.refreshOAuthToken(secretId);
  }

  async importCertificate(
    name: string,
    input: Omit<CertificateImportRequestInput, "name">,
  ): Promise<CertificateRef> {
    // Gate only — the parsed output is deliberately discarded so an omitted
    // auto_renew / renew_before_days stays undefined for the engine to fill
    // (the schema's defaults would pin them here). generateCsr uses its parsed
    // data instead because the superRefine pairing rules feed the manager call.
    const parsed = certificateImportSchema.safeParse({ name, ...input });
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }
    if (isEncryptedPrivateKeyPem(input.private_key_pem)) {
      throw VaultError.schemaValidation(ENCRYPTED_KEY_IMPORT_REFUSAL);
    }
    const manager = await this.loadCertManager();
    const ref = await manager.importCertificate(name, {
      privateKeyPem: input.private_key_pem,
      certificatePem: input.certificate_pem,
      chainPem: input.chain_pem,
      project: input.project,
      autoRenew: input.auto_renew,
      renewBeforeDays: input.renew_before_days,
    });
    return { handle: ref.handle, secretId: ref.secretId };
  }

  async generateCsr(
    name: string,
    input: Omit<GenerateCsrRequest, "name">,
  ): Promise<GeneratedCsrRef> {
    // The key-parameter pairing rules live in the schema's superRefine, so
    // validating here keeps one source for them: a mismatched bits/curve is
    // refused rather than silently ignored by the generator, and the message
    // matches what the REST route returns.
    const parsed = generateCsrRequestSchema.safeParse({ name, ...input });
    if (!parsed.success) {
      throw VaultError.schemaValidation(parsed.error.issues.map((i) => i.message).join(", "));
    }
    const manager = await this.loadCertManager();
    const csr = await manager.generateCsr(parsed.data.name, {
      commonName: parsed.data.subject,
      sans: parsed.data.sans,
      algorithm: parsed.data.algorithm ?? "ec",
      modulusLength: parsed.data.bits,
      namedCurve: parsed.data.curve,
      project: parsed.data.project,
    });
    return { handle: csr.handle, csrPem: csr.csrPem };
  }

  async renewCertificate(
    handle: string,
    options?: { httpPort?: number },
  ): Promise<CertificateStatus> {
    const secretId = await this.engine.resolveSecretId(handle);
    const manager = await this.loadCertManager();
    return manager.renewCertificate(secretId, { httpPort: options?.httpPort });
  }

  async getCertificateStatus(handle: string): Promise<CertificateStatus> {
    const secretId = await this.engine.resolveSecretId(handle);
    return this.engine.getCertificateStatus(secretId);
  }

  private async loadOAuthManager(): Promise<OAuthManagerT> {
    if (!this.oauthManagerInstance) {
      const { OAuthManager } = await import("@harpoc/oauth-proxy");
      this.oauthManagerInstance = new OAuthManager(this.engine, {
        // The SDK never runs the browser leg: the embedder follows auth_url.
        openBrowser: async () => {},
        // Ephemeral per flow, so concurrent or resumed flows cannot
        // EADDRINUSE-collide; the bound port is what the redirect URI carries.
        callbackPort: 0,
        onBackgroundFlowError:
          this.onBackgroundFlowError ??
          ((secretId, err): void => {
            process.stderr.write(
              `[harpoc] OAuth background flow failed (${secretId}): ${err instanceof Error ? err.message : String(err)}\n`,
            );
          }),
      });
    }
    return this.oauthManagerInstance;
  }

  private async loadCertManager(): Promise<CertManagerT> {
    if (!this.certManagerInstance) {
      const { CertManager } = await import("@harpoc/cert-manager");
      this.certManagerInstance = new CertManager(this.engine);
    }
    return this.certManagerInstance;
  }
}
