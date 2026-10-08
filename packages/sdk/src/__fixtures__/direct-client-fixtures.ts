/**
 * The DirectClient suites' shared doubles (SDK-7): a mock VaultEngine, fake OAuth and
 * certificate managers, the full injection policy and three PEM stand-ins. Test-only —
 * excluded from the build by `tsconfig.json` (TM-10).
 */
import { vi } from "vitest";
import type { Mock } from "vitest";
import { VaultState } from "@harpoc/shared";
import type { OAuthTokenStatus } from "@harpoc/shared";

export const FULL_POLICY = {
  url_allowlist: [] as string[],
  command_allowlist: ["gh"],
  env_allowlist: [] as string[],
  host_allowlist: [] as string[],
  response_mode: "filtered" as const,
  response_header_allowlist: [] as string[],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [] as string[],
  imap_read_only: false,
  strict_tree_exit: false,
};

/** The VaultEngine methods DirectClient calls, each a vitest mock. */
export interface MockEngine {
  getState: Mock;
  listSecrets: Mock;
  createSecret: Mock;
  getSecretInfo: Mock;
  getSecretValue: Mock;
  rotateSecret: Mock;
  revokeSecret: Mock;
  useSecret: Mock;
  setInjectionPolicy: Mock;
  getInjectionPolicy: Mock;
  setMcpServerConfig: Mock;
  getMcpServerConfig: Mock;
  setConnectionConfig: Mock;
  getConnectionConfig: Mock;
  deleteConnectionConfig: Mock;
  resolveSecretId: Mock;
  grantPolicy: Mock;
  revokePolicy: Mock;
  listPolicies: Mock;
  queryAudit: Mock;
  registerAgent: Mock;
  listAgents: Mock;
  getAgent: Mock;
  updateAgent: Mock;
  deactivateAgent: Mock;
  activateAgent: Mock;
  deleteAgent: Mock;
  listAgentPolicies: Mock;
  setAgentPermissions: Mock;
  listIssuedTokens: Mock;
  revokeToken: Mock;
  getOAuthTokenStatus: Mock;
  refreshOAuthToken: Mock;
  importCertificate: Mock;
  getCertificateStatus: Mock;
}

export function createMockEngine(): MockEngine {
  return {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    listSecrets: vi.fn().mockReturnValue([
      {
        handle: "secret://key",
        name: "key",
        type: "api_key",
        project: null,
        status: "active",
        version: 1,
        createdAt: 1000,
        updatedAt: 1000,
        expiresAt: null,
        rotatedAt: null,
      },
    ]),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://k",
      status: "created",
      message: "Secret created",
    }),
    getSecretInfo: vi.fn().mockResolvedValue({
      handle: "secret://key",
      name: "key",
      type: "api_key",
      project: null,
      status: "active",
      version: 1,
      createdAt: 1000,
      updatedAt: 1000,
      expiresAt: null,
      rotatedAt: null,
    }),
    getSecretValue: vi.fn().mockResolvedValue(new Uint8Array([72, 101, 108, 108, 111])),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    useSecret: vi.fn().mockResolvedValue({ type: "http", status: 200, body: "ok" }),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    getInjectionPolicy: vi.fn().mockResolvedValue({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
    }),
    setMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    getMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    setConnectionConfig: vi.fn().mockResolvedValue(undefined),
    getConnectionConfig: vi.fn().mockResolvedValue(undefined),
    deleteConnectionConfig: vi.fn().mockResolvedValue(true),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-1"),
    grantPolicy: vi.fn().mockReturnValue({
      id: "p1",
      secret_id: "uuid-1",
      principal_type: "agent",
      principal_id: "a1",
      permissions: ["read"],
      created_at: Date.now(),
      expires_at: null,
      created_by: "sdk-direct",
    }),
    revokePolicy: vi.fn(),
    listPolicies: vi.fn().mockReturnValue([]),
    queryAudit: vi.fn().mockReturnValue([]),
    registerAgent: vi.fn().mockReturnValue({
      id: "agent-1",
      name: "deploy-bot",
      description: null,
      owner: null,
      status: "active",
      created_at: 1000,
      updated_at: 1000,
      deactivated_at: null,
      last_active_at: null,
      active_tokens: 0,
      grants: 0,
    }),
    listAgents: vi.fn().mockReturnValue([]),
    getAgent: vi.fn().mockReturnValue({
      id: "agent-1",
      name: "deploy-bot",
      description: null,
      owner: null,
      status: "active",
      created_at: 1000,
      updated_at: 1000,
      deactivated_at: null,
      last_active_at: null,
      active_tokens: 0,
      grants: 0,
    }),
    updateAgent: vi.fn().mockReturnValue({
      id: "agent-1",
      name: "deploy-bot",
      description: "updated",
      owner: null,
      status: "active",
      created_at: 1000,
      updated_at: 2000,
      deactivated_at: null,
      last_active_at: null,
      active_tokens: 0,
      grants: 0,
    }),
    deactivateAgent: vi.fn().mockReturnValue({ revoked_tokens: 2 }),
    activateAgent: vi.fn().mockReturnValue({
      id: "agent-1",
      name: "deploy-bot",
      description: null,
      owner: null,
      status: "active",
      created_at: 1000,
      updated_at: 3000,
      deactivated_at: null,
      last_active_at: null,
      active_tokens: 0,
      grants: 0,
    }),
    deleteAgent: vi.fn().mockReturnValue({ revoked_tokens: 1, removed_grants: 3 }),
    listAgentPolicies: vi.fn().mockReturnValue([]),
    setAgentPermissions: vi.fn().mockReturnValue({
      policy: {
        id: "p1",
        secret_id: "uuid-1",
        principal_type: "agent",
        principal_id: "deploy-bot",
        permissions: ["read"],
        created_at: Date.now(),
        expires_at: null,
        created_by: "sdk-direct",
      },
      gated_before: false,
      gated_after: true,
    }),
    listIssuedTokens: vi.fn().mockReturnValue([]),
    revokeToken: vi.fn(),
    getOAuthTokenStatus: vi.fn().mockReturnValue({
      secret_id: "uuid-1",
      provider: "github",
      has_access_token: true,
      access_token_expires_at: 4000,
      has_refresh_token: true,
      last_refreshed_at: 3000,
      refresh_status: "ok",
      token_endpoint_auth_method: "client_secret_post",
    } satisfies OAuthTokenStatus),
    refreshOAuthToken: vi.fn().mockResolvedValue(9999),
    importCertificate: vi.fn().mockResolvedValue({ handle: "secret://web", secretId: "uuid-web" }),
    getCertificateStatus: vi.fn().mockReturnValue({
      secret_id: "uuid-1",
      subject: "CN=web.example.com",
      issuer: "CN=Test CA",
      not_before: 1000,
      not_after: 2000,
      auto_renew: false,
      renewal_status: "ok",
    }),
  };
}

/** The OAuthManager surface DirectClient drives, each a vitest mock. */
export interface FakeOAuthManager {
  cancelPendingFlows: Mock;
  startClientCredentials: Mock;
  startDeviceCode: Mock;
  startAuthorizationCodeDeferred: Mock;
}

export function createFakeOAuthManager(): FakeOAuthManager {
  return {
    cancelPendingFlows: vi.fn(),
    startClientCredentials: vi.fn().mockResolvedValue({
      handle: "secret://cc",
      status: "authorized",
      message: "Client credentials flow completed for github",
    }),
    startDeviceCode: vi.fn().mockResolvedValue({
      handle: "secret://dev",
      status: "pending_authorization",
      auth_url: "https://github.com/login/device",
      user_code: "ABCD-1234",
      message: "Please visit https://github.com/login/device and enter code: ABCD-1234",
      completion: Promise.resolve(),
    }),
    startAuthorizationCodeDeferred: vi.fn().mockResolvedValue({
      handle: "secret://ac",
      secretId: "uuid-ac",
      authUrl: "https://github.com/login/oauth/authorize?client_id=cid",
      completion: Promise.resolve(),
    }),
  };
}

/** The CertManager surface DirectClient drives, each a vitest mock. */
export interface FakeCertManager {
  importCertificate: Mock;
  generateCsr: Mock;
  renewCertificate: Mock;
}

export function createFakeCertManager(): FakeCertManager {
  return {
    importCertificate: vi.fn().mockResolvedValue({ handle: "secret://web", secretId: "uuid-web" }),
    generateCsr: vi.fn().mockResolvedValue({
      handle: "secret://web",
      secretId: "uuid-web",
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nr\n-----END CERTIFICATE REQUEST-----",
    }),
    renewCertificate: vi.fn().mockResolvedValue({
      secret_id: "uuid-web",
      subject: "CN=web.example.com",
      issuer: "CN=Test CA",
      not_before: 1000,
      not_after: 5000,
      auto_renew: true,
      renewal_status: "ok",
    }),
  };
}

export const PLAIN_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----";
export const ENCRYPTED_KEY_PEM =
  "-----BEGIN ENCRYPTED PRIVATE KEY-----\nk\n-----END ENCRYPTED PRIVATE KEY-----";
export const LEAF_PEM = "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----";
