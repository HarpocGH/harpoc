import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, it, expect, vi } from "vitest";
import {
  ENCRYPTED_KEY_IMPORT_REFUSAL,
  ErrorCode,
  HARPOC_VERSION,
  VaultError,
  VaultState,
} from "@harpoc/shared";
import type { McpServerConfigInput } from "@harpoc/shared";
import { DirectClient } from "./direct-client.js";
import {
  ENCRYPTED_KEY_PEM,
  FULL_POLICY,
  LEAF_PEM,
  PLAIN_KEY_PEM,
  createFakeCertManager,
  createFakeOAuthManager,
  createMockEngine,
} from "./__fixtures__/direct-client-fixtures.js";
import { expectVaultError } from "@harpoc/test-utils";

afterEach(() => {
  vi.restoreAllMocks();
});

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
    expect(engine.getSecretValue).toHaveBeenCalledWith("secret://key");
  });

  it("createSecret maps the wire shape to the engine input", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const result = await client.createSecret({ name: "k", type: "api_key", expires_at: 123 });
    expect(result.handle).toBe("secret://k");
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
      ...FULL_POLICY,
      url_allowlist: ["https://api.github.com/*"],
      command_allowlist: ["gh"],
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

    const policy = { ...FULL_POLICY, command_allowlist: ["python"] };
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
    expect(engine.setMcpServerConfig).toHaveBeenCalledWith("secret://key", {
      ...config,
      protocol: "2025-11-25",
    });

    const got = await client.getMcpServerConfig("secret://key");
    expect(engine.getMcpServerConfig).toHaveBeenCalledWith("secret://key");
    expect(got).toBeUndefined();
  });

  it("setMcpServerConfig refuses an unsupported transport through the shared schema", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const error = await expectVaultError(
      () =>
        client.setMcpServerConfig("secret://key", {
          server_name: "github-mcp",
          transport: "sse",
          command: "node",
          env_var: "GITHUB_TOKEN",
        } as unknown as McpServerConfigInput),
      ErrorCode.SCHEMA_VALIDATION_ERROR,
    );
    expect(error.message).toContain("transport: must be one of stdio, http");
    expect(engine.setMcpServerConfig).not.toHaveBeenCalled();
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

  it("setConnectionConfig refuses an unknown key through the shared schema before the engine sees it", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const error = await expectVaultError(
      () =>
        client.setConnectionConfig("secret://key", {
          database: { tls_mode: "require" },
          stray: 1,
        } as never),
      ErrorCode.SCHEMA_VALIDATION_ERROR,
    );
    expect(error.message).toBe('<root>: Unrecognized key: "stray"');
    expect(engine.setConnectionConfig).not.toHaveBeenCalled();
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

  it("revokePolicy hands the engine the secret id it resolved (REST parity)", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    await client.revokePolicy("secret://key", "p1");
    expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://key");
    expect(engine.listPolicies).not.toHaveBeenCalled();
    expect(engine.revokePolicy).toHaveBeenCalledWith("p1", undefined, "uuid-1");
  });

  it("revokePolicy refuses a policy belonging to another secret (IDOR guard)", async () => {
    const engine = createMockEngine();
    engine.revokePolicy.mockImplementation(() => {
      throw new VaultError(ErrorCode.POLICY_NOT_FOUND, "Policy not found: p1");
    });
    const client = new DirectClient(engine as never);

    await expect(client.revokePolicy("secret://key", "p1")).rejects.toMatchObject({
      code: "POLICY_NOT_FOUND",
    });
    expect(engine.listPolicies).not.toHaveBeenCalled();
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

  describe("agent governance", () => {
    it("registerAgent delegates to engine with no caller (trusted local path)", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const input = { name: "deploy-bot", description: "d", owner: "o" };
      const agent = await client.registerAgent(input);

      expect(agent.name).toBe("deploy-bot");
      expect(engine.registerAgent).toHaveBeenCalledWith(input);
    });

    it("listAgents delegates to engine with the default status", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.listAgents();
      expect(engine.listAgents).toHaveBeenCalledWith(undefined);
    });

    it("listAgents forwards an explicit status", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.listAgents("all");
      expect(engine.listAgents).toHaveBeenCalledWith("all");
    });

    it("getAgent delegates to engine", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const agent = await client.getAgent("deploy-bot");
      expect(agent.name).toBe("deploy-bot");
      expect(engine.getAgent).toHaveBeenCalledWith("deploy-bot");
    });

    it("updateAgent delegates to engine", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const input = { description: "updated" };
      const agent = await client.updateAgent("deploy-bot", input);
      expect(agent.description).toBe("updated");
      expect(engine.updateAgent).toHaveBeenCalledWith("deploy-bot", input);
    });

    it("deactivateAgent delegates to engine", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const result = await client.deactivateAgent("deploy-bot");
      expect(result).toEqual({ revoked_tokens: 2 });
      expect(engine.deactivateAgent).toHaveBeenCalledWith("deploy-bot");
    });

    it("activateAgent delegates to engine", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const agent = await client.activateAgent("deploy-bot");
      expect(agent.name).toBe("deploy-bot");
      expect(engine.activateAgent).toHaveBeenCalledWith("deploy-bot");
    });

    it("deleteAgent delegates to engine", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const result = await client.deleteAgent("deploy-bot");
      expect(result).toEqual({ revoked_tokens: 1, removed_grants: 3 });
      expect(engine.deleteAgent).toHaveBeenCalledWith("deploy-bot");
    });

    it("listAgentPolicies delegates to engine", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.listAgentPolicies("deploy-bot");
      expect(engine.listAgentPolicies).toHaveBeenCalledWith("deploy-bot");
    });

    it("setAgentPermissions resolves the handle and delegates with sdk-direct as createdBy", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const result = await client.setAgentPermissions("deploy-bot", "secret://key", {
        permissions: ["read"],
      });

      expect(result.gated_after).toBe(true);
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://key");
      expect(engine.setAgentPermissions).toHaveBeenCalledWith(
        "deploy-bot",
        "uuid-1",
        ["read"],
        undefined,
        "sdk-direct",
      );
    });

    it("setAgentPermissions forwards an explicit expiry", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.setAgentPermissions("deploy-bot", "secret://key", {
        permissions: ["read", "rotate"],
        expires_at: 5000,
      });

      expect(engine.setAgentPermissions).toHaveBeenCalledWith(
        "deploy-bot",
        "uuid-1",
        ["read", "rotate"],
        5000,
        "sdk-direct",
      );
    });

    it("passes no caller on any governance operation (trusted local path)", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.registerAgent({ name: "deploy-bot" });
      await client.listAgents();
      await client.getAgent("deploy-bot");
      await client.updateAgent("deploy-bot", {});
      await client.deactivateAgent("deploy-bot");
      await client.activateAgent("deploy-bot");
      await client.deleteAgent("deploy-bot");
      await client.listAgentPolicies("deploy-bot");
      await client.setAgentPermissions("deploy-bot", "secret://key", { permissions: [] });
      await client.listTokens();
      await client.revokeToken("jti-1");

      for (const fn of [
        engine.registerAgent,
        engine.listAgents,
        engine.getAgent,
        engine.updateAgent,
        engine.deactivateAgent,
        engine.activateAgent,
        engine.deleteAgent,
        engine.listAgentPolicies,
        engine.listIssuedTokens,
        engine.revokeToken,
      ]) {
        const call = fn.mock.calls[0] as unknown[];
        expect(call[call.length - 1]).not.toEqual(
          expect.objectContaining({ principal_type: expect.anything() }),
        );
      }
      // setAgentPermissions passes createdBy "sdk-direct" as its fifth
      // argument and no sixth (caller) argument at all.
      const setCall = engine.setAgentPermissions.mock.calls[0] as unknown[];
      expect(setCall).toHaveLength(5);
    });
  });

  describe("issued tokens", () => {
    it("listTokens delegates to engine with no options", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.listTokens();
      expect(engine.listIssuedTokens).toHaveBeenCalledWith({ agent: undefined, status: undefined });
    });

    it("listTokens forwards agent and status filters", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.listTokens({ agent: "deploy-bot", status: "active" });
      expect(engine.listIssuedTokens).toHaveBeenCalledWith({
        agent: "deploy-bot",
        status: "active",
      });
    });

    it("revokeToken delegates to engine with one argument", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      await client.revokeToken("jti-1");
      expect(engine.revokeToken).toHaveBeenCalledWith("jti-1");
      const call = engine.revokeToken.mock.calls[0] as unknown[];
      expect(call).toHaveLength(1);
    });
  });

  it("getHealth returns state and version", async () => {
    const engine = createMockEngine();
    const client = new DirectClient(engine as never);

    const health = await client.getHealth();
    expect(health.state).toBe(VaultState.UNLOCKED);
    expect(health.version).toBe(HARPOC_VERSION);
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
      let hits = 0;
      const stub = createServer((_req, res) => {
        hits += 1;
        res.writeHead(500).end();
      });
      await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
      const { port } = stub.address() as AddressInfo;

      try {
        const result = await client.startOAuthFlow({
          name: "gh",
          provider: "custom",
          grant_type: "authorization_code",
          client_id: "cid",
          auth_endpoint: "https://auth.example.test/authorize",
          token_endpoint: `http://127.0.0.1:${port}/token`,
        });
        expect(result.status).toBe("pending_authorization");

        const redirectUri = new URL(result.auth_url as string).searchParams.get("redirect_uri");
        const res = await fetch(`${redirectUri}?code=x&state=not-the-state`);
        expect(res.status).toBe(400);

        await vi.waitFor(() => expect(events).toHaveLength(1));
        expect(events[0]?.secretId).toBe("uuid-gh");
        expect(events[0]?.err).toBeInstanceOf(VaultError);
        expect(events[0]?.err).toMatchObject({ code: ErrorCode.OAUTH_INVALID_STATE });
        expect(hits).toBe(0);
      } finally {
        client.close();
        stub.close();
      }
    });

    // RED before startOAuthFlow's post-import re-check. With the manager
    // injected, the loader resolves on a warm client without ever yielding to
    // a close(): the close() below lands in the loader's own await, after the
    // loader's check has already passed, so only the re-check after the peer
    // import can see it — and without that re-check an auth-code start binds a
    // callback socket on a client the embedder has already shut down. The pin
    // depends on that order: with the import above the loader, the loader's
    // check would refuse instead and the row would pass vacuously; there is no
    // ordering-free way to observe the window.
    it("startOAuthFlow racing close() on a warm client starts no flow", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });

      const pending = client.startOAuthFlow({
        name: "gh",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "cid",
      });
      pending.catch(() => {});
      client.close();

      await expect(pending).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
        message: "DirectClient is closed",
      });
      expect(oauthManager.startAuthorizationCodeDeferred).not.toHaveBeenCalled();
      expect(oauthManager.startDeviceCode).not.toHaveBeenCalled();
      expect(oauthManager.startClientCredentials).not.toHaveBeenCalled();
    });

    // RED with the closed check below the injected-instance return: the rule
    // covers a manager handed in through DirectClientOptions exactly as it
    // covers one the client built for itself.
    it("refuses an injected OAuth manager after close()", async () => {
      const engine = createMockEngine();
      const oauthManager = createFakeOAuthManager();
      const client = new DirectClient(engine as never, { oauthManager: oauthManager as never });
      const internals = client as never as { loadOAuthManager(): Promise<unknown> };

      client.close();

      await expect(internals.loadOAuthManager()).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
        message: "DirectClient is closed",
      });
    });

    it("refuses an injected CertManager after close()", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });
      const internals = client as never as { loadCertManager(): Promise<unknown> };

      client.close();

      await expect(internals.loadCertManager()).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
        message: "DirectClient is closed",
      });
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

    it("importCertificate hands the engine the parsed defaults (false / 30)", async () => {
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
        autoRenew: false,
        renewBeforeDays: 30,
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
        code: ErrorCode.ENCRYPTED_KEY_UNSUPPORTED,
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

    it("renewCertificate resolves the handle and calls the manager with the id alone (B23)", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, {
        certManager: certManager as never,
      });

      const status = await client.renewCertificate("secret://web");

      expect(status.renewal_status).toBe("ok");
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://web");
      expect(certManager.renewCertificate).toHaveBeenCalledWith("uuid-1");
    });

    it("getCertificateStatus resolves the handle and passes no caller", async () => {
      const engine = createMockEngine();
      const client = new DirectClient(engine as never);

      const status = await client.getCertificateStatus("secret://web");

      expect(status.subject).toBe("CN=web.example.com");
      expect(engine.resolveSecretId).toHaveBeenCalledWith("secret://web");
      expect(engine.getCertificateStatus).toHaveBeenCalledWith("uuid-1");
    });

    it("importCertificate names the missing field the way the REST route does", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.importCertificate("web", { certificate_pem: LEAF_PEM } as never),
      ).rejects.toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_ERROR,
        message: "private_key_pem: Invalid input: expected string, received undefined",
      });
    });

    it("importCertificate names every missing field, path-prefixed and semicolon-joined", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(client.importCertificate("web", {} as never)).rejects.toMatchObject({
        message:
          "private_key_pem: Invalid input: expected string, received undefined; certificate_pem: Invalid input: expected string, received undefined",
      });
    });

    it("generateCsr renders an enum refusal value-free with the shared wording", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.generateCsr("web", { subject: "CN=web", algorithm: "dsa" } as never),
      ).rejects.toMatchObject({
        code: ErrorCode.SCHEMA_VALIDATION_ERROR,
        message: "algorithm: must be one of rsa, ec",
      });
    });

    it("generateCsr prefixes the pairing refusal with its path", async () => {
      const engine = createMockEngine();
      const certManager = createFakeCertManager();
      const client = new DirectClient(engine as never, { certManager: certManager as never });

      await expect(
        client.generateCsr("web", { subject: "CN=web", algorithm: "ec", bits: 4096 } as never),
      ).rejects.toMatchObject({ message: 'bits: bits applies only to algorithm "rsa"' });
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
