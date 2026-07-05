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
    getInjectionPolicy: vi
      .fn()
      .mockResolvedValue({ url_allowlist: [], command_allowlist: [], env_allowlist: [] }),
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

    const policy = { url_allowlist: ["https://api.github.com/*"], command_allowlist: ["gh"], env_allowlist: [] };
    await client.setInjectionPolicy("secret://key", policy);
    expect(engine.setInjectionPolicy).toHaveBeenCalledWith("secret://key", policy);

    const got = await client.getInjectionPolicy("secret://key");
    expect(engine.getInjectionPolicy).toHaveBeenCalledWith("secret://key");
    expect(got.command_allowlist).toEqual([]);
  });

  it("grantPolicy resolves secret ID and delegates", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const policy = await client.grantPolicy("secret://key", {
      principalType: "agent",
      principalId: "a1",
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

  it("revokePolicy delegates to engine", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.revokePolicy("secret://key", "p1");
    expect(engine.revokePolicy).toHaveBeenCalledWith("p1");
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
