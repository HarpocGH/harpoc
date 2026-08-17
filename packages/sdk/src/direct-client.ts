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
  ErrorCode,
  VAULT_VERSION,
  VaultError,
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
}

const PENDING_AUTHORIZATION_MESSAGE =
  "Authorize in the browser at auth_url; the token is stored automatically when the callback arrives. Poll the status route until refresh_status is ok.";

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

  constructor(
    private readonly engine: VaultEngine,
    options?: DirectClientOptions,
  ) {
    this.oauthManagerInstance = options?.oauthManager;
    this.certManagerInstance = options?.certManager;
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
    const { providerConfigFromFlowInput } = await import("@harpoc/oauth-proxy");
    const manager = await this.loadOAuthManager();
    const { config, project } = providerConfigFromFlowInput(input);

    if (input.grant_type === "client_credentials") {
      if (!config.client_secret) {
        throw VaultError.schemaValidation(
          "client_secret is required for the client_credentials grant",
        );
      }
      const result = await manager.startClientCredentials(input.name, config, project);
      return { handle: result.handle, status: result.status, message: result.message };
    }
    if (input.grant_type === "device_code") {
      const device = await manager.startDeviceCode(input.name, config, project);
      // Field by field: `completion` is the background poll's promise, which
      // the caller neither owns nor awaits.
      return {
        handle: device.handle,
        status: device.status,
        auth_url: device.auth_url,
        user_code: device.user_code,
        message: device.message,
      };
    }
    const start = await manager.startAuthorizationCodeDeferred(input.name, config, project);
    // Field by field: neither the internal `secretId` nor the `completion`
    // promise is the caller's (D2 — the browser leg finishes in background).
    return {
      handle: start.handle,
      status: "pending_authorization",
      auth_url: start.authUrl,
      message: PENDING_AUTHORIZATION_MESSAGE,
    };
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
    if (isEncryptedPrivateKeyPem(input.private_key_pem)) {
      throw VaultError.schemaValidation(
        "private_key_pem is passphrase-protected — decrypt it first or import via 'harpoc cert import', which prompts for the passphrase (D3)",
      );
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
