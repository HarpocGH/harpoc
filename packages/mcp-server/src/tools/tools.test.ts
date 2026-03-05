import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretInfo } from "@harpoc/core";
import type { VaultEngine } from "@harpoc/core";
import { InjectionGuard } from "../guards/injection-guard.js";
import { RateLimiter } from "../guards/rate-limiter.js";
import { ScopeGuard } from "../guards/scope-guard.js";
import { registerListSecrets } from "./list-secrets.js";
import { registerGetSecretInfo } from "./get-secret-info.js";
import { registerUseSecret } from "./use-secret.js";
import { registerCreateSecret } from "./create-secret.js";
import { registerRotateSecret } from "./rotate-secret.js";
import { registerRevokeSecret } from "./revoke-secret.js";
import { registerCheckHealth } from "./check-health.js";

function mockEngine(): VaultEngine {
  return {
    listSecrets: vi.fn().mockReturnValue([
      {
        handle: "secret://my-key",
        name: "my-key",
        type: "api_key",
        project: null,
        status: "active",
        version: 1,
        createdAt: 1000,
        updatedAt: 2000,
        expiresAt: null,
        rotatedAt: null,
      },
      {
        handle: "secret://prod/db-pass",
        name: "db-pass",
        type: "api_key",
        project: "prod",
        status: "active",
        version: 2,
        createdAt: 1000,
        updatedAt: 3000,
        expiresAt: null,
        rotatedAt: 2000,
      },
    ] satisfies SecretInfo[]),
    getSecretInfo: vi.fn().mockResolvedValue({
      handle: "secret://my-key",
      name: "my-key",
      type: "api_key",
      project: null,
      status: "active",
      version: 1,
      createdAt: 1000,
      updatedAt: 2000,
      expiresAt: null,
      rotatedAt: null,
    } satisfies SecretInfo),
    useSecret: vi.fn().mockResolvedValue({
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"ok":true}',
    }),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://new-key",
      status: "pending",
      message: "Secret created without value",
    }),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([]),
  } as unknown as VaultEngine;
}

function getToolText(result: { content: Array<{ type: string; text: string }> }): string {
  return (result.content[0] as { text: string }).text;
}

async function callTool(
  server: McpServer,
  name: string,
  args: Record<string, unknown>,
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  const lowLevelServer = (
    server as unknown as { server: { _requestHandlers: Map<string, unknown> } }
  ).server;
  const handler = lowLevelServer._requestHandlers.get("tools/call") as (
    req: { method: string; params: { name: string; arguments?: Record<string, unknown> } },
    extra: unknown,
  ) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

  if (!handler) throw new Error("No tools/call handler found");

  return handler(
    { method: "tools/call", params: { name, arguments: args } },
    { signal: new AbortController().signal, sessionId: "test" },
  );
}

describe("MCP Tools", () => {
  let server: McpServer;
  let engine: VaultEngine;
  let scopeGuard: ScopeGuard;
  let rateLimiter: RateLimiter;
  let injectionGuard: InjectionGuard;

  beforeEach(() => {
    server = new McpServer({ name: "test", version: "0.0.0" });
    engine = mockEngine();
    scopeGuard = new ScopeGuard(null);
    rateLimiter = new RateLimiter();
    injectionGuard = new InjectionGuard();
  });

  describe("list_secrets", () => {
    beforeEach(() => {
      registerListSecrets(server, engine, scopeGuard, rateLimiter);
    });

    it("returns metadata array", async () => {
      const result = await callTool(server, "list_secrets", {});
      const data = JSON.parse(getToolText(result));
      expect(data).toHaveLength(2);
      expect(data[0].handle).toBe("secret://my-key");
      expect(data[0].name).toBe("my-key");
    });

    it("never includes secret values", async () => {
      const result = await callTool(server, "list_secrets", {});
      const text = getToolText(result);
      expect(text).not.toContain("value");
      expect(text).not.toContain("ciphertext");
    });

    it("filters by project", async () => {
      await callTool(server, "list_secrets", { project: "prod" });
      expect(engine.listSecrets).toHaveBeenCalledWith("prod");
    });

    it("filters by type", async () => {
      const result = await callTool(server, "list_secrets", { type: "certificate" });
      const data = JSON.parse(getToolText(result));
      expect(data).toHaveLength(0);
    });

    it("filters by status", async () => {
      const result = await callTool(server, "list_secrets", { status: "active" });
      const data = JSON.parse(getToolText(result));
      expect(data).toHaveLength(2);
    });
  });

  describe("get_secret_info", () => {
    beforeEach(() => {
      registerGetSecretInfo(server, engine, scopeGuard, rateLimiter);
    });

    it("returns secret metadata", async () => {
      const result = await callTool(server, "get_secret_info", { handle: "secret://my-key" });
      const data = JSON.parse(getToolText(result));
      expect(data.handle).toBe("secret://my-key");
      expect(data.name).toBe("my-key");
      expect(data.type).toBe("api_key");
    });

    it("never includes secret value", async () => {
      const result = await callTool(server, "get_secret_info", { handle: "secret://my-key" });
      const text = getToolText(result);
      expect(text).not.toContain("value");
      expect(text).not.toContain("ciphertext");
    });
  });

  describe("use_secret", () => {
    beforeEach(() => {
      registerUseSecret(server, engine, scopeGuard, rateLimiter, injectionGuard);
    });

    it("returns sanitized HTTP response", async () => {
      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        request: { method: "GET", url: "https://api.example.com/data" },
        injection: { type: "bearer" },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.status).toBe(200);
      expect(data.body).toBe('{"ok":true}');
    });

    it("sanitizes credential patterns in response", async () => {
      (engine.useSecret as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 200,
        body: "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature leaked!",
      });

      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        request: { method: "GET", url: "https://api.example.com/data" },
        injection: { type: "bearer" },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.body).toContain("[REDACTED]");
      expect(data.body).not.toContain("eyJhbG");
    });

    it("calls engine.useSecret with correct args", async () => {
      await callTool(server, "use_secret", {
        handle: "secret://my-key",
        request: { method: "POST", url: "https://api.example.com/data", body: "test" },
        injection: { type: "header", header_name: "X-API-Key" },
        follow_redirects: "none",
      });

      expect(engine.useSecret).toHaveBeenCalledWith(
        "secret://my-key",
        expect.objectContaining({
          method: "POST",
          url: "https://api.example.com/data",
          body: "test",
        }),
        { type: "header", header_name: "X-API-Key" },
        "none",
      );
    });
  });

  describe("create_secret", () => {
    beforeEach(() => {
      registerCreateSecret(server, engine, scopeGuard, rateLimiter);
    });

    it("creates secret without value (pending status)", async () => {
      const result = await callTool(server, "create_secret", {
        name: "new-key",
        type: "api_key",
      });
      const data = JSON.parse(getToolText(result));
      expect(data.handle).toBe("secret://new-key");
      expect(data.status).toBe("pending");
      expect(data.message).toContain("harpoc secret set");
    });

    it("passes project and injection to engine", async () => {
      await callTool(server, "create_secret", {
        name: "new-key",
        type: "api_key",
        project: "prod",
        injection: { type: "bearer" },
      });

      expect(engine.createSecret).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "new-key",
          type: "api_key",
          project: "prod",
          injection: { type: "bearer" },
        }),
      );
    });

    it("has no value parameter", async () => {
      await callTool(server, "create_secret", {
        name: "new-key",
        type: "api_key",
      });

      const calls = (engine.createSecret as ReturnType<typeof vi.fn>).mock.calls;
      const call = (calls[0] as [Record<string, unknown>])[0];
      expect(call).not.toHaveProperty("value");
    });
  });

  describe("rotate_secret", () => {
    beforeEach(() => {
      registerRotateSecret(server, engine, scopeGuard, rateLimiter);
    });

    it("returns pending_rotation status with CLI hint", async () => {
      const result = await callTool(server, "rotate_secret", { handle: "secret://my-key" });
      const data = JSON.parse(getToolText(result));
      expect(data.status).toBe("pending_rotation");
      expect(data.message).toContain("harpoc secret rotate");
    });

    it("does not call engine.rotateSecret (deferred)", async () => {
      await callTool(server, "rotate_secret", { handle: "secret://my-key" });
      expect(engine.rotateSecret).not.toHaveBeenCalled();
    });
  });

  describe("revoke_secret", () => {
    beforeEach(() => {
      registerRevokeSecret(server, engine, scopeGuard, rateLimiter);
    });

    it("calls engine.revokeSecret", async () => {
      await callTool(server, "revoke_secret", { handle: "secret://my-key" });
      expect(engine.revokeSecret).toHaveBeenCalledWith("secret://my-key");
    });

    it("returns confirmation", async () => {
      const result = await callTool(server, "revoke_secret", { handle: "secret://my-key" });
      const data = JSON.parse(getToolText(result));
      expect(data.status).toBe("revoked");
    });
  });

  describe("check_secret_health", () => {
    beforeEach(() => {
      registerCheckHealth(server, engine, scopeGuard, rateLimiter);
    });

    it("returns status counts", async () => {
      const result = await callTool(server, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));
      expect(data.vault_state).toBe("unlocked");
      expect(data.total_secrets).toBe(2);
      expect(data.by_status.active).toBe(2);
    });

    it("identifies expiring secrets", async () => {
      const now = Date.now();
      (engine.listSecrets as ReturnType<typeof vi.fn>).mockReturnValue([
        {
          handle: "secret://expiring",
          name: "expiring",
          type: "api_key",
          project: null,
          status: "active",
          version: 1,
          createdAt: 1000,
          updatedAt: 2000,
          expiresAt: now + 3 * 24 * 60 * 60 * 1000,
          rotatedAt: null,
        },
      ]);

      const result = await callTool(server, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));
      expect(data.expiring_soon).toHaveLength(1);
      expect(data.expiring_soon[0].handle).toBe("secret://expiring");
    });
  });

  describe("scope enforcement", () => {
    it("denies access when token lacks permission", async () => {
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as const,
        iat: 0,
        exp: 9999999999,
        jti: "j",
      };
      const restrictedGuard = new ScopeGuard(token);
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCreateSecret(srv, engine, restrictedGuard, rateLimiter);

      const result = await callTool(srv, "create_secret", { name: "x", type: "api_key" });
      expect(result.isError).toBe(true);
      expect(getToolText(result)).toContain("Access denied");
    });
  });
});
