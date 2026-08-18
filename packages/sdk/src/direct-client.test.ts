import { describe, it, expect, vi } from "vitest";
import {
  ENCRYPTED_KEY_IMPORT_REFUSAL,
  ErrorCode,
  VAULT_VERSION,
  VaultError,
  VaultState,
} from "@harpoc/shared";
import type { OAuthTokenStatus } from "@harpoc/shared";
import { DirectClient } from "./direct-client.js";

function createMockEngine() {
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

function createFakeOAuthManager() {
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

function createFakeCertManager() {
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

const PLAIN_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----";
const ENCRYPTED_KEY_PEM =
  "-----BEGIN ENCRYPTED PRIVATE KEY-----\nk\n-----END ENCRYPTED PRIVATE KEY-----";
const LEAF_PEM = "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----";

describe("DirectClient", () => {
  it("listSecrets delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const result = await client.listSecrets("proj");
    expect(result).toHaveLength(1);
    expect(engine.listSecrets).toHaveBeenCalledWith("proj");
  });

  // W2: the in-process client is the trusted local path — it must forward no
  // caller, or enumeration would start filtering for embedders that never
  // authenticated through a token in the first place.
  it("listSecrets forwards no caller (trusted local path)", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.listSecrets();
    const call = engine.listSecrets.mock.calls[0] as unknown[];
    expect(call.length).toBeLessThanOrEqual(1);
    expect(call[1]).toBeUndefined();
  });

  it("getSecretInfo delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const info = await client.getSecretInfo("secret://key");
    expect(info.name).toBe("key");
    expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://key");
  });

  it("getSecretValue delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const value = await client.getSecretValue("secret://key");
    expect(Buffer.from(value).toString()).toBe("Hello");
  });

  it("createSecret delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const result = await client.createSecret({ name: "k", type: "api_key" });
    expect(result.handle).toBe("secret://k");
    expect(engine.createSecret).toHaveBeenCalled();
  });

  it("createSecret maps the wire shape to the engine input", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.createSecret({ name: "k", type: "api_key", expires_at: 123 });
    expect(engine.createSecret).toHaveBeenCalledWith({
      name: "k",
      type: "api_key",
      project: undefined,
      value: undefined,
      expiresAt: 123,
    });
  });

  it("rotateSecret delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.rotateSecret("secret://key", new Uint8Array([1, 2, 3]));
    expect(engine.rotateSecret).toHaveBeenCalledWith("secret://key", new Uint8Array([1, 2, 3]));
  });

  it("revokeSecret delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.revokeSecret("secret://key");
    expect(engine.revokeSecret).toHaveBeenCalledWith("secret://key");
  });

  it("useSecret delegates the action to the engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const action = {
      type: "http" as const,
      method: "GET" as const,
      url: "https://api.example.com",
      injection: { type: "bearer" as const },
      follow_redirects: "none" as const,
    };
    const result = await client.useSecret("secret://key", action);

    expect(result.type).toBe("http");
    expect(engine.useSecret).toHaveBeenCalledWith("secret://key", action);
  });

  it("useSecret delegates a process action to the engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const action = {
      type: "process" as const,
      command: "gh",
      args: ["api", "/user"],
      env_var: "GH_TOKEN",
    };
    await client.useSecret("secret://key", action);
    expect(engine.useSecret).toHaveBeenCalledWith("secret://key", action);
  });

  it("setInjectionPolicy and getInjectionPolicy delegate to the engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const policy = {
      url_allowlist: ["https://api.github.com/*"],
      command_allowlist: ["gh"],
      env_allowlist: [],
    };
    await client.setInjectionPolicy("secret://key", policy);
    expect(engine.setInjectionPolicy).toHaveBeenCalledWith("secret://key", policy, undefined);

    const got = await client.getInjectionPolicy("secret://key");
    expect(engine.getInjectionPolicy).toHaveBeenCalledWith("secret://key");
    expect(got.command_allowlist).toEqual([]);
  });

  it("setInjectionPolicy forwards the interpreter acknowledgement to the engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const policy = { url_allowlist: [], command_allowlist: ["python"], env_allowlist: [] };
    await client.setInjectionPolicy("secret://key", policy, { acknowledge_interpreters: true });
    expect(engine.setInjectionPolicy).toHaveBeenCalledWith("secret://key", policy, {
      acknowledge_interpreters: true,
    });
  });

  it("setMcpServerConfig and getMcpServerConfig delegate to the engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const config = {
      server_name: "github-mcp",
      transport: "stdio" as const,
      command: "node",
      args: ["server.js"],
      env_var: "GITHUB_TOKEN",
    };
    await client.setMcpServerConfig("secret://key", config);
    expect(engine.setMcpServerConfig).toHaveBeenCalledWith("secret://key", config);

    const got = await client.getMcpServerConfig("secret://key");
    expect(engine.getMcpServerConfig).toHaveBeenCalledWith("secret://key");
    expect(got).toBeUndefined();
  });

  it("connection-config methods delegate to the engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const config = { database: { tls_mode: "require" as const }, ssh: { known_hosts: ["h k v"] } };
    await client.setConnectionConfig("secret://key", config);
    expect(engine.setConnectionConfig).toHaveBeenCalledWith("secret://key", config);

    await client.getConnectionConfig("secret://key");
    expect(engine.getConnectionConfig).toHaveBeenCalledWith("secret://key");

    const deleted = await client.deleteConnectionConfig("secret://key");
    expect(engine.deleteConnectionConfig).toHaveBeenCalledWith("secret://key");
    expect(deleted).toBe(true);
  });

  it("passes no caller on the config and policy operations (trusted local path)", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    // In-process SDK callers authenticate by master password / session file
    // and are exempt from per-secret policies (thesis §4.7). A caller argument
    // appearing here would silently subject them to the engine's gate.
    await client.getInjectionPolicy("secret://key");
    await client.getMcpServerConfig("secret://key");
    await client.getConnectionConfig("secret://key");
    await client.deleteConnectionConfig("secret://key");
    await client.listPolicies("secret://key");

    expect(engine.getInjectionPolicy).toHaveBeenCalledWith("secret://key");
    expect(engine.getMcpServerConfig).toHaveBeenCalledWith("secret://key");
    expect(engine.getConnectionConfig).toHaveBeenCalledWith("secret://key");
    expect(engine.deleteConnectionConfig).toHaveBeenCalledWith("secret://key");
    expect(engine.listPolicies).toHaveBeenCalledWith("uuid-1");
  });

  it("grantPolicy resolves secret ID and delegates", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const policy = await client.grantPolicy("secret://key", {
      principal_type: "agent",
      principal_id: "a1",
      permissions: ["read"],
    });

    expect(policy.id).toBe("p1");
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://key");
    expect(engine.grantPolicy).toHaveBeenCalledWith(
      {
        secretId: "uuid-1",
        principalType: "agent",
        principalId: "a1",
        permissions: ["read"],
        expiresAt: undefined,
      },
      "sdk-direct",
    );
  });

  it("revokePolicy verifies ownership before revoking (REST parity)", async () => {
    const engine = createMockEngine();
    engine.listPolicies.mockReturnValue([{ id: "p1" }]);
    const client = new DirectClient(engine as never);

    await client.revokePolicy("secret://key", "p1");
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://key");
    expect(engine.listPolicies).toHaveBeenCalledWith("uuid-1");
    expect(engine.revokePolicy).toHaveBeenCalledWith("p1");
  });

  it("revokePolicy refuses a policy belonging to another secret (IDOR guard)", async () => {
    const engine = createMockEngine();
    engine.listPolicies.mockReturnValue([{ id: "other-policy" }]);
    const client = new DirectClient(engine as never);

    await expect(client.revokePolicy("secret://key", "p1")).rejects.toMatchObject({
      code: "POLICY_NOT_FOUND",
    });
    expect(engine.revokePolicy).not.toHaveBeenCalled();
  });

  it("listPolicies resolves secret ID and delegates", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.listPolicies("secret://key");
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://key");
    expect(engine.listPolicies).toHaveBeenCalledWith("uuid-1");
  });

  it("queryAudit delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.queryAudit({ limit: 10 });
    expect(engine.queryAudit).toHaveBeenCalledWith({ limit: 10 });
  });

  it("getHealth returns state and version", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const health = await client.getHealth();
    expect(health.state).toBe(VaultState.UNLOCKED);
    expect(health.version).toBe(VAULT_VERSION);
  });

  describe("oauth flows (injected manager)", () => {
    it("startOAuthFlow authorization_code returns the deferred start's auth URL", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      const result = await client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "cid",
      });

      expect(result.handle).toBe("secret://ac");
      expect(result.status).toBe("pending_authorization");
      expect(result.auth_url).toBe("https://github.com/login/oauth/authorize?client_id=cid");
      expect(result.message).toContain("auth_url");
      expect(oauthManager.startAuthorizationCodeDeferred).toHaveBeenCalledTimes(1);
    });

    it("the pending message points at a reachable completion signal", async () => {
      // refresh_status "ok" is unreachable for providers that issue no
      // refresh token; has_access_token flips on every successful flow.
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      const result = await client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "cid",
      });

      expect(result.message).toContain("has_access_token");
      expect(result.message).not.toContain("refresh_status");
    });

    // D2 parity with the REST route: the background browser leg's promise and
    // the internal secret ID are the host's, not the caller's.
    it("startOAuthFlow authorization_code exposes neither completion nor secretId", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      const result = await client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "cid",
      });

      expect("completion" in result).toBe(false);
      expect("secretId" in result).toBe(false);
      expect(Object.keys(result).sort()).toEqual(["auth_url", "handle", "message", "status"]);
    });

    it("startOAuthFlow device_code carries the user code but no completion", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      const result = await client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "device_code",
        client_id: "cid",
      });

      expect(result.user_code).toBe("ABCD-1234");
      expect(result.auth_url).toBe("https://github.com/login/device");
      expect("completion" in result).toBe(false);
    });

    it("startOAuthFlow client_credentials returns the authorized projection", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      const result = await client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "client_credentials",
        client_id: "cid",
        client_secret: "csec",
      });

      expect(result).toEqual({
        handle: "secret://cc",
        status: "authorized",
        message: "Client credentials flow completed for github",
      });
    });

    it("startOAuthFlow refuses client_credentials without a client secret", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      await expect(
        client.startOAuthFlow({
          name: "gh",
          provider: "github",
          grant_type: "client_credentials",
          client_id: "cid",
        }),
      ).rejects.toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_ERROR,
        message: expect.stringContaining("client_secret is required"),
      });
      expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
    });

    it("startOAuthFlow passes the project but no caller (trusted local path)", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      await client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "cid",
        project: "proj",
      });

      const call = oauthManager.startAuthorizationCodeDeferred.mock.calls[0] as unknown[];
      expect(call[0]).toBe("gh");
      expect(call[2]).toBe("proj");
      expect(call[3]).toBeUndefined();
    });

    it("getOAuthStatus resolves the handle and passes no caller", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const status = await client.getOAuthStatus("secret://gh");

      expect(status.refresh_status).toBe("ok");
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://gh");
      expect(engine.getOAuthTokenStatus).toHaveBeenCalledWith("uuid-1");
    });

    it("refreshOAuthToken resolves the handle and returns the new expiry", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      expect(await client.refreshOAuthToken("secret://gh")).toBe(9999);
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://gh");
      expect(engine.refreshOAuthToken).toHaveBeenCalledWith("uuid-1");
    });

    // RestClient pins the same null arm (a provider that issues no expiry);
    // without this the direct mode could coerce it to a number and the two
    // client modes would disagree on what "no expiry" looks like.
    it("refreshOAuthToken returns null when the engine reports no expiry", async () => {
      const engine = createMockEngine();
      engine.refreshOAuthToken.mockResolvedValueOnce(null);
      const client = new DirectClient(engine as never);

      expect(await client.refreshOAuthToken("secret://gh")).toBeNull();
    });
  });

  describe("close()", () => {
    it("cancels the injected manager's pending flows", () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      client.close();

      expect(oauthManager.cancelPendingFlows).toHaveBeenCalledTimes(1);
    });

    it("is a no-op before any OAuth use", () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      expect(() => client.close()).not.toThrow();
    });

    it("a background flow failure reaches options.onBackgroundFlowError through the lazily built manager", async () => {
      // End-to-end through the real OAuthManager: a wrong-state callback (the
      // CSRF guard) fails the background leg without any outbound network.
      // Without the option seam the manager's internal .catch swallows it and
      // the secret stays PENDING with no signal. An abort from close() is
      // deliberately NOT routed here (expected cancellation, filtered by the
      // manager) — only genuine failures reach the handler.
      const events: Array<{ secretId: string; err: unknown }> = [];
      const engine = createMockEngine();
      (engine as { createOAuthSecret?: unknown }).createOAuthSecret = vi
        .fn()
        .mockResolvedValue({ handle: "secret://gh", secretId: "uuid-gh" });
      const client = new DirectClient(engine as never, {
        onBackgroundFlowError: (secretId: string, err: unknown) => events.push({ secretId, err }),
      });

      try {
        const result = await client.startOAuthFlow({
          name: "gh",
          provider: "github",
          grant_type: "authorization_code",
          client_id: "cid",
        });
        expect(result.status).toBe("pending_authorization");

        const redirectUri = new URL(result.auth_url as string).searchParams.get("redirect_uri");
        const res = await fetch(`${redirectUri}?code=x&state=not-the-state`);
        expect(res.status).toBe(400);

        await vi.waitFor(() => expect(events).toHaveLength(1));
        expect(events[0]?.secretId).toBe("uuid-gh");
        expect(events[0]?.err).toBeInstanceOf(VaultError);
      } finally {
        client.close();
      }
    });
  });

  describe("certificates (injected manager)", () => {
    it("importCertificate maps the wire shape to the manager input", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      const ref = await client.importCertificate("web", {
        private_key_pem: PLAIN_KEY_PEM,
        certificate_pem: LEAF_PEM,
        chain_pem: undefined,
        project: "proj",
        auto_renew: true,
        renew_before_days: 14,
      });

      expect(ref).toEqual({ handle: "secret://web", secretId: "uuid-web" });
      expect(certManager.importCertificate).toHaveBeenCalledWith("web", {
        privateKeyPem: PLAIN_KEY_PEM,
        certificatePem: LEAF_PEM,
        chainPem: undefined,
        project: "proj",
        autoRenew: true,
        renewBeforeDays: 14,
      });
    });

    // The defaulted fields are the schema's / engine's to fill (both say
    // false / 30), so an omitting caller must reach the manager with them
    // undefined rather than with values the SDK invented.
    it("importCertificate leaves the omitted defaults undefined for the engine to fill", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await client.importCertificate("web", {
        private_key_pem: PLAIN_KEY_PEM,
        certificate_pem: LEAF_PEM,
      });

      expect(certManager.importCertificate).toHaveBeenCalledWith("web", {
        privateKeyPem: PLAIN_KEY_PEM,
        certificatePem: LEAF_PEM,
        chainPem: undefined,
        project: undefined,
        autoRenew: undefined,
        renewBeforeDays: undefined,
      });
    });

    it("importCertificate refuses a passphrase-protected key before the manager runs", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.importCertificate("web", {
          private_key_pem: ENCRYPTED_KEY_PEM,
          certificate_pem: LEAF_PEM,
        }),
      ).rejects.toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_ERROR,
        message: ENCRYPTED_KEY_IMPORT_REFUSAL,
      });
      expect(certManager.importCertificate).not.toHaveBeenCalled();
    });

    it("importCertificate refuses a missing private_key_pem with SCHEMA_VALIDATION_ERROR, not a TypeError", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.importCertificate("web", { certificate_pem: LEAF_PEM } as never),
      ).rejects.toMatchObject({ code: ErrorCode.SCHEMA_VALIDATION_ERROR });
      expect(certManager.importCertificate).not.toHaveBeenCalled();
    });

    it("importCertificate refuses a missing certificate_pem with SCHEMA_VALIDATION_ERROR, not a TypeError", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.importCertificate("web", { private_key_pem: PLAIN_KEY_PEM } as never),
      ).rejects.toMatchObject({ code: ErrorCode.SCHEMA_VALIDATION_ERROR });
      expect(certManager.importCertificate).not.toHaveBeenCalled();
    });

    it("generateCsr maps subject/bits/curve onto the manager input and strips secretId", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      const result = await client.generateCsr("web", {
        subject: "web.example.com",
        sans: ["www.example.com"],
        algorithm: "rsa",
        bits: 4096,
        project: "proj",
      });

      expect(result).toEqual({
        handle: "secret://web",
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nr\n-----END CERTIFICATE REQUEST-----",
      });
      expect(certManager.generateCsr).toHaveBeenCalledWith("web", {
        commonName: "web.example.com",
        sans: ["www.example.com"],
        algorithm: "rsa",
        modulusLength: 4096,
        namedCurve: undefined,
        project: "proj",
      });
    });

    // A mismatched key parameter is refused, not ignored (product contract):
    // EC generation drops modulusLength, so forwarding it would hand back a
    // P-256 key while the caller believes they asked for RSA-4096.
    it("generateCsr refuses bits without algorithm rsa, without reaching the manager", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.generateCsr("web", { subject: "web.example.com", bits: 4096 }),
      ).rejects.toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_ERROR,
        message: expect.stringContaining('bits applies only to algorithm "rsa"'),
      });
      expect(certManager.generateCsr).not.toHaveBeenCalled();
    });

    it("generateCsr refuses curve with algorithm rsa, without reaching the manager", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.generateCsr("web", {
          subject: "web.example.com",
          algorithm: "rsa",
          curve: "P-384",
        }),
      ).rejects.toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_ERROR,
        message: expect.stringContaining('curve applies only to algorithm "ec"'),
      });
      expect(certManager.generateCsr).not.toHaveBeenCalled();
    });

    it("generateCsr accepts the satisfied rsa/bits pairing", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      const result = await client.generateCsr("web", {
        subject: "web.example.com",
        algorithm: "rsa",
        bits: 4096,
      });

      expect(result.handle).toBe("secret://web");
      expect(certManager.generateCsr).toHaveBeenCalledWith(
        "web",
        expect.objectContaining({ algorithm: "rsa", modulusLength: 4096 }),
      );
    });

    it("generateCsr defaults the algorithm to ec (REST-route parity)", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await client.generateCsr("web", { subject: "web.example.com" });

      expect(certManager.generateCsr).toHaveBeenCalledWith(
        "web",
        expect.objectContaining({ algorithm: "ec" }),
      );
    });

    it("renewCertificate resolves the handle and forwards the http port", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      const status = await client.renewCertificate("secret://web", { httpPort: 8080 });

      expect(status.renewal_status).toBe("ok");
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://web");
      expect(certManager.renewCertificate).toHaveBeenCalledWith("uuid-1", { httpPort: 8080 });
    });

    it("getCertificateStatus resolves the handle and passes no caller", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const status = await client.getCertificateStatus("secret://web");

      expect(status.subject).toBe("CN=web.example.com");
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://web");
      expect(engine.getCertificateStatus).toHaveBeenCalledWith("uuid-1");
    });
  });

  /**
   * D4 says the OAuth and certificate peers are loaded by `import()` only when
   * one of their methods is actually called, and that each client builds its
   * manager once. Every other test here injects a fake, so the real dynamic
   * import ran only on the OAuth side (the background-failure test above) and
   * neither side pinned the cache — a lost `if (!this.xInstance)` would have
   * rebuilt a manager per call, silently.
   */
  describe("lazy optional peers (no injected manager)", () => {
    it("lazily builds the real CertManager when none is injected", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const ref = await client.importCertificate("web", {
        private_key_pem: PLAIN_KEY_PEM,
        certificate_pem: LEAF_PEM,
      });

      expect(ref).toEqual({ handle: "secret://web", secretId: "uuid-web" });
      // The real manager's own mapping: a bundle split into leaf + chain, then
      // the engine's positional signature. A fake could not produce this.
      expect(engine.importCertificate).toHaveBeenCalledWith(
        "web",
        PLAIN_KEY_PEM,
        {
          certificatePem: LEAF_PEM,
          chainPem: undefined,
          autoRenew: undefined,
          renewBeforeDays: undefined,
        },
        undefined,
        undefined,
      );
    });

    it("caches the lazily built managers (one instance per client)", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);
      // The cache is the property under test, so reference equality through the
      // private loaders is the honest pin — no public method exposes it.
      const load = client as never as {
        loadOAuthManager(): Promise<unknown>;
        loadCertManager(): Promise<unknown>;
      };

      try {
        expect(await load.loadOAuthManager()).toBe(await load.loadOAuthManager());
        expect(await load.loadCertManager()).toBe(await load.loadCertManager());
      } finally {
        client.close();
      }
    });
  });

  describe("error propagation", () => {
    it("propagates VAULT_LOCKED from engine", async () => {
      const engine = createMockEngine();
      engine.listSecrets.mockImplementation(() => {
        throw VaultError.vaultLocked();
      });
      const client = new DirectClient(engine as never);

      await expect(client.listSecrets()).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
      );
    });

    it("propagates SECRET_NOT_FOUND from engine", async () => {
      const engine = createMockEngine();
      engine.getSecretInfo.mockRejectedValue(VaultError.secretNotFound("missing"));
      const client = new DirectClient(engine as never);

      await expect(client.getSecretInfo("secret://missing")).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.SECRET_NOT_FOUND }),
      );
    });

    it("propagates ACCESS_DENIED from engine", async () => {
      const engine = createMockEngine();
      engine.getSecretValue.mockRejectedValue(VaultError.accessDenied("no permission"));
      const client = new DirectClient(engine as never);

      await expect(client.getSecretValue("secret://key")).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });
  });
});
