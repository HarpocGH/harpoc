import { describe, it, expect, vi, beforeEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretInfo } from "@harpoc/core";
import type { VaultEngine } from "@harpoc/core";
import type { ExpiringCertificateInfo, ExpiringOAuthTokenInfo } from "@harpoc/shared";
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
      type: "http",
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"ok":true}',
    }),
    createSecret: vi.fn().mockResolvedValue({
      handle: "secret://new-key",
      status: "pending",
      message: "Secret created without value",
    }),
    setSecretValue: vi.fn().mockResolvedValue(undefined),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-123"),
    getState: vi.fn().mockReturnValue("unlocked"),
    queryAudit: vi.fn().mockReturnValue([]),
    getExpiringOAuthTokenStatuses: vi.fn().mockReturnValue([]),
    getExpiringCertificateStatuses: vi.fn().mockReturnValue([]),
  } as unknown as VaultEngine;
}

function getToolText(result: { content: Array<{ type: string; text: string }> }): string {
  return (result.content[0] as { text: string }).text;
}

interface McpToolDescriptor {
  name: string;
  inputSchema: { properties?: Record<string, unknown> };
}

/** Advertised `tools/list` output — used by the v1.3 schema-widening pins below. */
async function listTools(server: McpServer): Promise<McpToolDescriptor[]> {
  const lowLevelServer = (
    server as unknown as { server: { _requestHandlers: Map<string, unknown> } }
  ).server;
  const handler = lowLevelServer._requestHandlers.get("tools/list") as (
    req: unknown,
    extra: unknown,
  ) => Promise<{ tools: McpToolDescriptor[] }>;
  const result = await handler(
    { method: "tools/list", params: {} },
    { signal: new AbortController().signal, sessionId: "test" },
  );
  return result.tools;
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
      expect(engine.listSecrets).toHaveBeenCalledWith("prod", undefined);
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

    it("returns a sanitized HTTP response", async () => {
      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: {
          type: "http",
          method: "GET",
          url: "https://api.example.com/data",
          injection: { type: "bearer" },
        },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.status).toBe(200);
      expect(data.body).toBe('{"ok":true}');
    });

    it("sanitizes credential patterns in an HTTP response", async () => {
      (engine.useSecret as ReturnType<typeof vi.fn>).mockResolvedValue({
        type: "http",
        status: 200,
        body: "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature leaked!",
      });

      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: {
          type: "http",
          method: "GET",
          url: "https://api.example.com/data",
          injection: { type: "bearer" },
        },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.body).toContain("[REDACTED]");
      expect(data.body).not.toContain("eyJhbG");
    });

    it("sanitizes credential patterns in process output", async () => {
      (engine.useSecret as ReturnType<typeof vi.fn>).mockResolvedValue({
        type: "process",
        exit_code: 0,
        stdout: "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature leaked!",
        stderr: "",
      });

      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: { type: "process", command: "gh", args: ["api"], env_var: "GH_TOKEN" },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.stdout).toContain("[REDACTED]");
      expect(data.stdout).not.toContain("eyJhbG");
    });

    it("passes the action to engine.useSecret", async () => {
      await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: {
          type: "http",
          method: "POST",
          url: "https://api.example.com/data",
          body: "test",
          injection: { type: "header", header_name: "X-API-Key" },
          follow_redirects: "none",
          response_mode: "status_only",
        },
      });

      // Tokenless (local full-access) mode passes no caller — the engine's
      // trusted local path, exempt from per-secret policies.
      expect(engine.useSecret).toHaveBeenCalledWith(
        "secret://my-key",
        expect.objectContaining({
          type: "http",
          method: "POST",
          url: "https://api.example.com/data",
          body: "test",
          injection: { type: "header", header_name: "X-API-Key" },
          follow_redirects: "none",
          response_mode: "status_only",
        }),
        undefined,
      );
    });

    it("rejects an invalid response_mode in the action", async () => {
      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: {
          type: "http",
          method: "GET",
          url: "https://api.example.com/data",
          injection: { type: "bearer" },
          response_mode: "raw",
        },
      });
      expect(result.isError).toBe(true);
      expect(engine.useSecret).not.toHaveBeenCalled();
    });

    it("returns a status_only-shaped result without body or headers keys", async () => {
      (engine.useSecret as ReturnType<typeof vi.fn>).mockResolvedValue({
        type: "http",
        status: 201,
      });

      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: {
          type: "http",
          method: "POST",
          url: "https://api.example.com/data",
          injection: { type: "bearer" },
          response_mode: "status_only",
        },
      });
      const data = JSON.parse(getToolText(result)) as Record<string, unknown>;
      expect(data.status).toBe(201);
      expect("body" in data).toBe(false);
      expect("headers" in data).toBe(false);
    });

    it("accepts an mcp action and returns the proxied result", async () => {
      (engine.useSecret as ReturnType<typeof vi.fn>).mockResolvedValue({
        type: "mcp",
        content: [{ type: "text", text: "downstream says hi" }],
      });

      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: { type: "mcp", server: "github-mcp", tool: "list_repositories" },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.type).toBe("mcp");
      expect(data.content[0].text).toBe("downstream says hi");

      expect(engine.useSecret).toHaveBeenCalledWith(
        "secret://my-key",
        expect.objectContaining({ type: "mcp", server: "github-mcp", tool: "list_repositories" }),
        undefined,
      );
    });

    it("sanitizes credential patterns in mcp content and structured_content", async () => {
      (engine.useSecret as ReturnType<typeof vi.fn>).mockResolvedValue({
        type: "mcp",
        content: [{ type: "text", text: "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature leaked!" }],
        structured_content: {
          note: "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature nested!",
        },
      });

      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: { type: "mcp", server: "github-mcp", tool: "leaky" },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.content[0].text).toContain("[REDACTED]");
      expect(data.content[0].text).not.toContain("eyJhbG");
      expect(data.structured_content.note).toContain("[REDACTED]");
      expect(data.structured_content.note).not.toContain("eyJhbG");
    });

    // v1.3: `action: useSecretActionSchema.describe(...)` IS the shared
    // schema (design §7.3) — nothing here hand-copies the action union, so
    // MCP's advertised tools/list schema must widen automatically the moment
    // the shared schema gains an arm. These pins read the actual advertised
    // JSON schema (via tools/list), not the Zod source, so a regression to a
    // hand-maintained MCP-side copy would fail them.
    describe("advertised action schema (v1.3 context widening pin)", () => {
      interface AnyOfArm {
        properties?: Record<string, { const?: string }>;
      }

      async function actionArms(): Promise<AnyOfArm[]> {
        const tools = await listTools(server);
        const tool = tools.find((t) => t.name === "use_secret");
        expect(tool).toBeDefined();
        const actionSchema = (tool as McpToolDescriptor).inputSchema.properties?.action as
          | { anyOf?: AnyOfArm[] }
          | undefined;
        expect(actionSchema?.anyOf).toBeDefined();
        return actionSchema?.anyOf ?? [];
      }

      function armFor(arms: AnyOfArm[], type: string): AnyOfArm {
        const arm = arms.find((a) => a.properties?.type?.const === type);
        expect(arm).toBeDefined();
        return arm as AnyOfArm;
      }

      it("advertises 11 action arms — the shared 11-type union crossed the MCP boundary unmodified", async () => {
        const arms = await actionArms();
        expect(arms).toHaveLength(11);
      });

      it("advertises the smtp arm's exact key set", async () => {
        const arm = armFor(await actionArms(), "smtp");
        expect(Object.keys(arm.properties ?? {}).sort()).toEqual(
          [
            "type",
            "host",
            "port",
            "security",
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "text",
            "html",
            "headers",
            "attachments",
            "timeout_ms",
          ].sort(),
        );
      });

      it("advertises the imap arm's exact key set", async () => {
        const arm = armFor(await actionArms(), "imap");
        expect(Object.keys(arm.properties ?? {}).sort()).toEqual(
          ["type", "host", "port", "mailbox", "account", "operation", "timeout_ms"].sort(),
        );
      });

      it("advertises the websocket arm's exact key set", async () => {
        const arm = armFor(await actionArms(), "websocket");
        expect(Object.keys(arm.properties ?? {}).sort()).toEqual(
          [
            "type",
            "url",
            "injection",
            "message",
            "subprotocols",
            "collect",
            "response_mode",
            "timeout_ms",
          ].sort(),
        );
      });

      it("advertises the ssh arm's exact key set", async () => {
        const arm = armFor(await actionArms(), "ssh");
        expect(Object.keys(arm.properties ?? {}).sort()).toEqual(
          ["type", "host", "user", "command", "port", "timeout_ms"].sort(),
        );
      });

      it("advertises the sftp arm's exact key set", async () => {
        const arm = armFor(await actionArms(), "sftp");
        expect(Object.keys(arm.properties ?? {}).sort()).toEqual(
          [
            "type",
            "host",
            "user",
            "port",
            "operation",
            "remote_path",
            "local_path",
            "timeout_ms",
          ].sort(),
        );
      });

      it("advertises the docker_registry arm's exact key set", async () => {
        const arm = armFor(await actionArms(), "docker_registry");
        expect(Object.keys(arm.properties ?? {}).sort()).toEqual(
          ["type", "operation", "image", "timeout_ms"].sort(),
        );
      });
    });

    it("rejects a malformed smtp action at the schema boundary (-32602)", async () => {
      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: {
          type: "smtp",
          host: "smtp.example.com",
          from: "not-an-email",
          to: ["ops@example.com"],
          subject: "hi",
          text: "hi",
        },
      });
      expect(result.isError).toBe(true);
      expect(getToolText(result)).toContain("-32602");
      expect(engine.useSecret).not.toHaveBeenCalled();
    });

    it("sanitizes credential patterns in a websocket result (new-context guard pin)", async () => {
      (engine.useSecret as ReturnType<typeof vi.fn>).mockResolvedValue({
        type: "websocket",
        messages: ["Bearer eyJhbGciOiJIUzI1NiJ9.test.signature leaked!"],
        close_code: 1000,
      });

      const result = await callTool(server, "use_secret", {
        handle: "secret://my-key",
        action: {
          type: "websocket",
          url: "wss://echo.example.com/socket",
          injection: { type: "bearer" },
        },
      });
      const data = JSON.parse(getToolText(result));
      expect(data.messages[0]).toContain("[REDACTED]");
      expect(data.messages[0]).not.toContain("eyJhbG");
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

    it("passes project to engine and drops a legacy injection config", async () => {
      await callTool(server, "create_secret", {
        name: "new-key",
        type: "api_key",
        project: "prod",
        injection: { type: "bearer" },
      });

      expect(engine.createSecret).toHaveBeenCalledWith(
        expect.objectContaining({ name: "new-key", type: "api_key", project: "prod" }),
        // Tokenless guard in this suite: the trusted local path passes no
        // caller, so the row stays NULL-principal (L3 control).
        undefined,
      );
      const calls = (engine.createSecret as ReturnType<typeof vi.fn>).mock.calls;
      const call = (calls[0] as [Record<string, unknown>])[0];
      expect(call).not.toHaveProperty("injection");
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

    // M10b: every call opens a URL-mode value collector (a loopback listener
    // plus a timer). Only the very generous global tier applied, so the
    // per-secret tier is now bucketed by the requested name.
    it("is bucketed by name in the per-secret rate-limit tier", () => {
      const spy = vi.spyOn(rateLimiter, "checkLimit");
      return callTool(server, "create_secret", { name: "new-key", type: "api_key" }).then(() => {
        expect(spy).toHaveBeenCalledWith(expect.stringContaining("new-key"));
      });
    });

    it("refuses once the per-secret tier is exhausted", async () => {
      const limiter = new RateLimiter(10_000, 3);
      const limited = new McpServer({ name: "t", version: "0.0.0" });
      registerCreateSecret(limited, engine, scopeGuard, limiter);

      for (let i = 0; i < 3; i++) {
        await callTool(limited, "create_secret", { name: "same-key", type: "api_key" });
      }
      const result = await callTool(limited, "create_secret", {
        name: "same-key",
        type: "api_key",
      });
      expect(getToolText(result)).toContain("rate limit");
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
      expect(engine.revokeSecret).toHaveBeenCalledWith("secret://my-key", undefined);
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

    it("excludes out-of-scope secrets for a name-pattern-scoped token", async () => {
      const now = Date.now();
      const expiresAt = now + 3 * 24 * 60 * 60 * 1000;
      (engine.listSecrets as ReturnType<typeof vi.fn>).mockReturnValue([
        {
          handle: "secret://db-prod",
          name: "db-prod",
          type: "api_key",
          project: null,
          status: "active",
          version: 1,
          createdAt: 1000,
          updatedAt: 2000,
          expiresAt,
          rotatedAt: null,
        },
        {
          handle: "secret://api-key",
          name: "api-key",
          type: "api_key",
          project: null,
          status: "revoked",
          version: 1,
          createdAt: 1000,
          updatedAt: 2000,
          expiresAt,
          rotatedAt: null,
        },
      ]);
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as "list"[],
        secrets: ["db-*"],
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCheckHealth(srv, engine, new ScopeGuard(token), rateLimiter);

      const result = await callTool(srv, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));
      expect(data.total_secrets).toBe(1);
      expect(data.by_status).toEqual({ active: 1 });
      expect(data.expiring_soon).toHaveLength(1);
      expect(data.expiring_soon[0].handle).toBe("secret://db-prod");
      expect(getToolText(result)).not.toContain("api-key");
    });

    it("excludes out-of-scope secrets for a project-scoped token", async () => {
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as "list"[],
        project: "prod",
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCheckHealth(srv, engine, new ScopeGuard(token), rateLimiter);

      const result = await callTool(srv, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));
      expect(data.total_secrets).toBe(1);
      expect(getToolText(result)).not.toContain("my-key");
    });

    function oauthItem(overrides: Partial<ExpiringOAuthTokenInfo> = {}): ExpiringOAuthTokenInfo {
      return {
        handle: "secret://gh-token",
        name: "gh-token",
        project: null,
        provider: "github",
        access_token_expires_at: 1_000,
        has_refresh_token: true,
        refresh_status: "ok",
        ...overrides,
      };
    }

    function certItem(overrides: Partial<ExpiringCertificateInfo> = {}): ExpiringCertificateInfo {
      return {
        handle: "secret://my-cert",
        name: "my-cert",
        project: null,
        subject: "CN=example.com",
        not_after: 2_000,
        auto_renew: true,
        renew_before_days: 30,
        renewal_status: "expiring_soon",
        ...overrides,
      };
    }

    it("includes oauth_refresh_needed and certificates_nearing_renewal with the exact D5 key sets", async () => {
      (engine.getExpiringOAuthTokenStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        oauthItem(),
      ]);
      (engine.getExpiringCertificateStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        certItem(),
      ]);

      const result = await callTool(server, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));

      expect(data.oauth_refresh_needed).toHaveLength(1);
      expect(Object.keys(data.oauth_refresh_needed[0]).sort()).toEqual([
        "access_token_expires_at",
        "handle",
        "has_refresh_token",
        "name",
        "project",
        "provider",
        "refresh_status",
      ]);
      expect(data.certificates_nearing_renewal).toHaveLength(1);
      expect(Object.keys(data.certificates_nearing_renewal[0]).sort()).toEqual([
        "auto_renew",
        "handle",
        "name",
        "not_after",
        "project",
        "renew_before_days",
        "renewal_status",
        "subject",
      ]);
    });

    it("passes the scope guard's caller and a one-hour window to the engine projections", async () => {
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as "list"[],
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const guard = new ScopeGuard(token);
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCheckHealth(srv, engine, guard, rateLimiter);

      await callTool(srv, "check_secret_health", {});

      expect(engine.getExpiringOAuthTokenStatuses).toHaveBeenCalledWith(
        60 * 60 * 1000,
        guard.caller,
      );
      expect(engine.getExpiringCertificateStatuses).toHaveBeenCalledWith(guard.caller);
      expect(guard.caller).not.toBeUndefined();
    });

    it("a project-scoped token filters out-of-project oauth/cert items", async () => {
      (engine.getExpiringOAuthTokenStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        oauthItem({ handle: "secret://prod/gh-token", name: "gh-token", project: "prod" }),
        oauthItem({ handle: "secret://dev/gh-token", name: "gh-token", project: "dev" }),
      ]);
      (engine.getExpiringCertificateStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        certItem({ handle: "secret://prod/my-cert", name: "my-cert", project: "prod" }),
        certItem({ handle: "secret://dev/my-cert", name: "my-cert", project: "dev" }),
      ]);
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as "list"[],
        project: "prod",
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCheckHealth(srv, engine, new ScopeGuard(token), rateLimiter);

      const result = await callTool(srv, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));

      expect(data.oauth_refresh_needed).toHaveLength(1);
      expect(data.oauth_refresh_needed[0].handle).toBe("secret://prod/gh-token");
      expect(data.certificates_nearing_renewal).toHaveLength(1);
      expect(data.certificates_nearing_renewal[0].handle).toBe("secret://prod/my-cert");
      expect(getToolText(result)).not.toContain("dev/");
    });

    it("a name-pattern-scoped token filters non-matching oauth/cert items", async () => {
      (engine.getExpiringOAuthTokenStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        oauthItem({ handle: "secret://db-prod", name: "db-prod" }),
        oauthItem({ handle: "secret://api-key", name: "api-key" }),
      ]);
      (engine.getExpiringCertificateStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        certItem({ handle: "secret://db-prod", name: "db-prod" }),
        certItem({ handle: "secret://api-key", name: "api-key" }),
      ]);
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as "list"[],
        secrets: ["db-*"],
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCheckHealth(srv, engine, new ScopeGuard(token), rateLimiter);

      const result = await callTool(srv, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));

      expect(data.oauth_refresh_needed).toHaveLength(1);
      expect(data.oauth_refresh_needed[0].handle).toBe("secret://db-prod");
      expect(data.certificates_nearing_renewal).toHaveLength(1);
      expect(data.certificates_nearing_renewal[0].handle).toBe("secret://db-prod");
      expect(getToolText(result)).not.toContain("api-key");
    });

    it("a project-scoped token drops project-less oauth/cert items", async () => {
      (engine.getExpiringOAuthTokenStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        oauthItem({ handle: "secret://prod/gh-token", name: "gh-token", project: "prod" }),
        oauthItem({ handle: "secret://global-token", name: "global-token", project: null }),
      ]);
      (engine.getExpiringCertificateStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        certItem({ handle: "secret://prod/my-cert", name: "my-cert", project: "prod" }),
        certItem({ handle: "secret://global-cert", name: "global-cert", project: null }),
      ]);
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as "list"[],
        project: "prod",
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCheckHealth(srv, engine, new ScopeGuard(token), rateLimiter);

      const result = await callTool(srv, "check_secret_health", {});
      const data = JSON.parse(getToolText(result));

      expect(data.oauth_refresh_needed).toHaveLength(1);
      expect(data.oauth_refresh_needed[0].handle).toBe("secret://prod/gh-token");
      expect(data.certificates_nearing_renewal).toHaveLength(1);
      expect(data.certificates_nearing_renewal[0].handle).toBe("secret://prod/my-cert");
      expect(getToolText(result)).not.toContain("global-");
    });

    it("args.handle narrows both oauth_refresh_needed and certificates_nearing_renewal", async () => {
      (engine.getExpiringOAuthTokenStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        oauthItem({ handle: "secret://a", name: "a" }),
        oauthItem({ handle: "secret://b", name: "b" }),
      ]);
      (engine.getExpiringCertificateStatuses as ReturnType<typeof vi.fn>).mockReturnValue([
        certItem({ handle: "secret://a", name: "a" }),
        certItem({ handle: "secret://b", name: "b" }),
      ]);

      const result = await callTool(server, "check_secret_health", { handle: "secret://a" });
      const data = JSON.parse(getToolText(result));

      expect(data.oauth_refresh_needed).toHaveLength(1);
      expect(data.oauth_refresh_needed[0].handle).toBe("secret://a");
      expect(data.certificates_nearing_renewal).toHaveLength(1);
      expect(data.certificates_nearing_renewal[0].handle).toBe("secret://a");
    });
  });

  describe("scope enforcement", () => {
    it("denies access when token lacks permission", async () => {
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["list"] as "list"[],
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const restrictedGuard = new ScopeGuard(token);
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCreateSecret(srv, engine, restrictedGuard, rateLimiter);

      const result = await callTool(srv, "create_secret", { name: "x", type: "api_key" });
      expect(result.isError).toBe(true);
      expect(getToolText(result)).toContain("Access denied");
    });

    it("denies create_secret for a name outside the token's name patterns", async () => {
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["create"] as "create"[],
        secrets: ["api-*"],
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCreateSecret(srv, engine, new ScopeGuard(token), rateLimiter);

      const denied = await callTool(srv, "create_secret", {
        name: "admin-backdoor",
        type: "api_key",
      });
      expect(denied.isError).toBe(true);
      expect(getToolText(denied)).toContain("Access denied");
      expect(engine.createSecret).not.toHaveBeenCalled();

      const allowed = await callTool(srv, "create_secret", { name: "api-new", type: "api_key" });
      expect(allowed.isError).not.toBe(true);
      // L3: the create row is attributed to the requesting principal — it read
      // as a NULL-principal trusted-local operation before.
      expect(engine.createSecret).toHaveBeenCalledWith(
        expect.objectContaining({ name: "api-new" }),
        expect.objectContaining({ principal_id: "test", interface: "mcp" }),
      );
    });

    it("denies global create_secret for a project-scoped token", async () => {
      const token = {
        sub: "test",
        vault_id: "v",
        scope: ["create"] as "create"[],
        project: "prod",
        iat: 0,
        exp: 9999999999,
        jti: "j",
        principal_type: "agent" as const,
      };
      const srv = new McpServer({ name: "test", version: "0.0.0" });
      registerCreateSecret(srv, engine, new ScopeGuard(token), rateLimiter);

      const denied = await callTool(srv, "create_secret", { name: "x", type: "api_key" });
      expect(denied.isError).toBe(true);
      expect(getToolText(denied)).toContain("Access denied");
      expect(engine.createSecret).not.toHaveBeenCalled();

      const allowed = await callTool(srv, "create_secret", {
        name: "x",
        type: "api_key",
        project: "prod",
      });
      expect(allowed.isError).not.toBe(true);
      expect(engine.createSecret).toHaveBeenCalledWith(
        expect.objectContaining({ name: "x", project: "prod" }),
        expect.objectContaining({ principal_id: "test", project: "prod" }),
      );
    });
  });
});

describe("token-derived caller wiring (engine-level policy enforcement)", () => {
  const TOKEN = {
    sub: "agent-7",
    vault_id: "vault-1",
    scope: ["use", "read", "rotate", "revoke", "create"] as (
      | "use"
      | "read"
      | "rotate"
      | "revoke"
      | "create"
    )[],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-caller",
    principal_type: "tool" as const,
    project: "api",
  };
  const EXPECTED_CALLER = {
    principal_type: "tool",
    principal_id: "agent-7",
    project: "api",
    interface: "mcp",
  };

  let server: McpServer;
  let engine: VaultEngine;

  beforeEach(() => {
    server = new McpServer({ name: "test", version: "0.0.0" });
    engine = mockEngine();
    (engine.getSecretInfo as ReturnType<typeof vi.fn>).mockResolvedValue({
      handle: "secret://api/my-key",
      name: "my-key",
      type: "api_key",
      project: "api",
      status: "active",
      version: 1,
      createdAt: 1000,
      updatedAt: 2000,
      expiresAt: null,
      rotatedAt: null,
    });
    const scopeGuard = new ScopeGuard(TOKEN);
    const rateLimiter = new RateLimiter();
    const injectionGuard = new InjectionGuard();
    registerUseSecret(server, engine, scopeGuard, rateLimiter, injectionGuard);
    registerGetSecretInfo(server, engine, scopeGuard, rateLimiter);
    registerRevokeSecret(server, engine, scopeGuard, rateLimiter);
  });

  it("use_secret passes the token-derived caller to the engine", async () => {
    await callTool(server, "use_secret", {
      handle: "secret://api/my-key",
      action: {
        type: "http",
        method: "GET",
        url: "https://api.example.com/data",
        injection: { type: "bearer" },
      },
    });
    expect(engine.useSecret).toHaveBeenCalledWith(
      "secret://api/my-key",
      expect.objectContaining({ type: "http" }),
      EXPECTED_CALLER,
    );
  });

  it("get_secret_info passes the caller to the engine", async () => {
    await callTool(server, "get_secret_info", { handle: "secret://api/my-key" });
    expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://api/my-key", EXPECTED_CALLER);
  });

  it("revoke_secret passes the caller to the engine", async () => {
    await callTool(server, "revoke_secret", { handle: "secret://api/my-key" });
    expect(engine.revokeSecret).toHaveBeenCalledWith("secret://api/my-key", EXPECTED_CALLER);
  });

  it("create_secret passes the caller to the out-of-band value set", async () => {
    // Drive the real URL-elicitation channel: declare the capability, then
    // answer the elicitation by posting into the one-time form the tool opened.
    const inner = (server as unknown as { server: Record<string, unknown> }).server;
    inner.getClientCapabilities = (): unknown => ({ elicitation: { url: {} } });
    inner.createElicitationCompletionNotifier = (): (() => Promise<void>) => () =>
      Promise.resolve();
    inner.elicitInput = async (params: { url: string }): Promise<{ action: string }> => {
      await fetch(params.url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "value=browser-entered",
      });
      return { action: "accept" };
    };
    (engine.createSecret as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      handle: "secret://api/api-new",
      status: "pending",
      message: "",
    });
    registerCreateSecret(server, engine, new ScopeGuard(TOKEN), new RateLimiter());

    await callTool(server, "create_secret", { name: "api-new", type: "api_key", project: "api" });

    expect(engine.setSecretValue).toHaveBeenCalledWith(
      "secret://api/api-new",
      expect.anything(),
      EXPECTED_CALLER,
    );
  });
});
