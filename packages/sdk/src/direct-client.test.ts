import { describe, it, expect, vi } from "vitest";
import { ErrorCode, VAULT_VERSION, VaultError, VaultState } from "@harpoc/shared";
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
  };
}

describe("DirectClient", () => {
  it("listSecrets delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const result = await client.listSecrets("proj");
    expect(result).toHaveLength(1);
    expect(engine.listSecrets).toHaveBeenCalledWith("proj");
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
