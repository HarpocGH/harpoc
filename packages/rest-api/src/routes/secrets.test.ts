import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { RateLimiter } from "../middleware/rate-limit.js";
import { createSecretRoutes } from "./secrets.js";
import type { HarpocEnv } from "../types.js";

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["list", "read", "create", "rotate", "revoke", "use"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
};

function createMockEngine() {
  return {
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    listSecrets: vi.fn().mockReturnValue([
      {
        handle: "secret://test-key",
        name: "test-key",
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
      handle: "secret://new-key",
      status: "created",
      message: "Secret created",
    }),
    getSecretInfo: vi.fn().mockResolvedValue({
      handle: "secret://test-key",
      name: "test-key",
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
    revokeSecret: vi.fn().mockResolvedValue(undefined),
    rotateSecret: vi.fn().mockResolvedValue(undefined),
    useSecret: vi.fn().mockResolvedValue({
      type: "http",
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"ok":true}',
    }),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    getInjectionPolicy: vi.fn().mockResolvedValue({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
    }),
    setMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    getMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    deleteMcpServerConfig: vi.fn().mockResolvedValue(true),
    setConnectionConfig: vi.fn().mockResolvedValue(undefined),
    getConnectionConfig: vi.fn().mockResolvedValue(undefined),
    deleteConnectionConfig: vi.fn().mockResolvedValue(true),
    resolveSecretId: vi.fn().mockResolvedValue("secret-uuid-1"),
  };
}

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = new Hono<HarpocEnv>();
  app.onError(errorHandler);
  const limiter = new RateLimiter();
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    c.set("limiter", limiter);
    await next();
  });
  app.use("/api/v1/secrets", authMiddleware);
  app.use("/api/v1/secrets/*", authMiddleware);
  app.route("/api/v1/secrets", createSecretRoutes());
});

const AUTH = { authorization: "Bearer valid-jwt" };

describe("secret routes", () => {
  describe("GET /api/v1/secrets", () => {
    it("lists secrets", async () => {
      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].name).toBe("test-key");
    });

    it("passes project query param to engine", async () => {
      await app.request("/api/v1/secrets?project=myproj", { headers: AUTH });
      expect(engine.listSecrets).toHaveBeenCalledWith("myproj");
    });

    it("rejects without auth", async () => {
      const res = await app.request("/api/v1/secrets");
      expect(res.status).toBe(401);
    });

    it("rejects if token lacks list scope", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read"] });
      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/v1/secrets", () => {
    it("creates a secret", async () => {
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key" }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.handle).toBe("secret://new-key");
    });

    it("creates a secret with base64 value", async () => {
      const value = Buffer.from("my-secret-value").toString("base64");
      await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key", value }),
      });

      const call = engine.createSecret.mock.calls[0] as Array<{ value?: Uint8Array }>;
      expect(call[0].value).toBeInstanceOf(Uint8Array);
      expect(Buffer.from(call[0].value as Uint8Array).toString()).toBe("my-secret-value");
    });

    it("rejects if token lacks create scope", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read"] });
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key" }),
      });
      expect(res.status).toBe(403);
    });
  });

  describe("GET /api/v1/secrets/:handle", () => {
    it("returns secret info", async () => {
      const res = await app.request("/api/v1/secrets/test-key", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.name).toBe("test-key");
      expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://test-key");
    });

    it("returns 404 for unknown secret", async () => {
      engine.getSecretInfo.mockRejectedValue(VaultError.secretNotFound("unknown"));
      const res = await app.request("/api/v1/secrets/unknown", { headers: AUTH });
      expect(res.status).toBe(404);
    });
  });

  describe("GET /api/v1/secrets/:handle/value", () => {
    it("returns secret value as base64", async () => {
      const res = await app.request("/api/v1/secrets/test-key/value", { headers: AUTH });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.value).toBe(Buffer.from("Hello").toString("base64"));
    });
  });

  describe("DELETE /api/v1/secrets/:handle", () => {
    it("revokes secret with confirm=true", async () => {
      const res = await app.request("/api/v1/secrets/test-key?confirm=true", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      expect(engine.revokeSecret).toHaveBeenCalledWith("secret://test-key");
    });

    it("rejects without confirm=true", async () => {
      const res = await app.request("/api/v1/secrets/test-key", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe(ErrorCode.INVALID_INPUT);
    });

    it("rejects if token lacks revoke scope", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["read"] });
      const res = await app.request("/api/v1/secrets/test-key?confirm=true", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/v1/secrets/:handle/rotate", () => {
    it("rotates a secret", async () => {
      const value = Buffer.from("new-value").toString("base64");
      const res = await app.request("/api/v1/secrets/test-key/rotate", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ value }),
      });
      expect(res.status).toBe(200);
      expect(engine.rotateSecret).toHaveBeenCalled();

      const call = engine.rotateSecret.mock.calls[0] as [string, Uint8Array];
      expect(call[0]).toBe("secret://test-key");
      expect(Buffer.from(call[1]).toString()).toBe("new-value");
    });

    it("rejects without value", async () => {
      const res = await app.request("/api/v1/secrets/test-key/rotate", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("POST /api/v1/secrets/:handle/use", () => {
    it("executes an HTTP action with an injected secret", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: {
            type: "http",
            method: "GET",
            url: "https://api.example.com/data",
            injection: { type: "bearer" },
          },
        }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.status).toBe(200);
    });

    it("passes the action to the engine verbatim", async () => {
      await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: {
            type: "http",
            method: "GET",
            url: "https://api.example.com",
            timeout_ms: 5000,
            follow_redirects: "none",
            injection: { type: "bearer" },
          },
        }),
      });

      const call = engine.useSecret.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      const action = call[1] as { type: string; timeout_ms: number; follow_redirects: string };
      expect(action.type).toBe("http");
      expect(action.timeout_ms).toBe(5000);
      expect(action.follow_redirects).toBe("none");
    });

    it("executes a process action", async () => {
      engine.useSecret.mockResolvedValueOnce({
        type: "process",
        exit_code: 0,
        stdout: "done",
        stderr: "",
      });
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: { type: "process", command: "gh", args: ["api"], env_var: "GH_TOKEN" },
        }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.type).toBe("process");
      expect(body.data.exit_code).toBe(0);
    });
  });

  describe("POST /api/v1/secrets/:handle/use validation", () => {
    it("rejects a missing action", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    });

    it("rejects an invalid URL", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: { type: "http", method: "GET", url: "not-a-url", injection: { type: "bearer" } },
        }),
      });
      expect(res.status).toBe(400);
    });

    it("rejects a process action with an invalid env var name", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: { type: "process", command: "gh", env_var: "1BAD-NAME" },
        }),
      });
      expect(res.status).toBe(400);
    });

    it("sanitizes credential patterns in an HTTP response body", async () => {
      engine.useSecret.mockResolvedValueOnce({
        type: "http",
        status: 200,
        body: '{"error":"Invalid token: Bearer sk_live_abcdefghij1234567890"}',
      });
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: {
            type: "http",
            method: "GET",
            url: "https://api.example.com/data",
            injection: { type: "bearer" },
          },
        }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.body).not.toContain("sk_live_abcdefghij1234567890");
      expect(body.data.body).toContain("[REDACTED]");
    });

    it("sanitizes credential patterns in process stdout", async () => {
      engine.useSecret.mockResolvedValueOnce({
        type: "process",
        exit_code: 0,
        stdout: "leaked Bearer sk_live_abcdefghij1234567890 here",
        stderr: "",
      });
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: { type: "process", command: "gh", env_var: "GH_TOKEN" },
        }),
      });
      const body = await res.json();
      expect(body.data.stdout).not.toContain("sk_live_abcdefghij1234567890");
      expect(body.data.stdout).toContain("[REDACTED]");
    });

    it("accepts an mcp action and returns the proxied result", async () => {
      engine.useSecret.mockResolvedValueOnce({
        type: "mcp",
        content: [{ type: "text", text: "downstream result" }],
      });
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: { type: "mcp", server: "github-mcp", tool: "list_repositories" },
        }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.type).toBe("mcp");
      expect(body.data.content[0].text).toBe("downstream result");
    });

    it("rejects an mcp action without a tool", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ action: { type: "mcp", server: "github-mcp" } }),
      });
      expect(res.status).toBe(400);
    });

    it("sanitizes credential patterns in mcp content", async () => {
      engine.useSecret.mockResolvedValueOnce({
        type: "mcp",
        content: [{ type: "text", text: "Bearer sk_live_abcdefghij1234567890 leaked" }],
        structured_content: { note: "Bearer sk_live_abcdefghij1234567890 nested" },
      });
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: { type: "mcp", server: "github-mcp", tool: "leaky" },
        }),
      });
      const body = await res.json();
      expect(JSON.stringify(body)).not.toContain("sk_live_abcdefghij1234567890");
      expect(body.data.content[0].text).toContain("[REDACTED]");
      expect(body.data.structured_content.note).toContain("[REDACTED]");
    });
  });

  describe("injection-policy routes", () => {
    it("GET returns the policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "GET",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toEqual({
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [],
        response_mode: "filtered",
        response_header_allowlist: [],
      });
    });

    it("PUT sets the policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          command_allowlist: ["gh"],
          url_allowlist: ["https://api.github.com/*"],
          response_mode: "status_only",
          response_header_allowlist: ["Content-Type"],
        }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      expect((call[1] as { command_allowlist: string[] }).command_allowlist).toEqual(["gh"]);
      const policy = call[1] as { response_mode: string; response_header_allowlist: string[] };
      expect(policy.response_mode).toBe("status_only");
      expect(policy.response_header_allowlist).toEqual(["Content-Type"]);
    });

    it("PUT omitting response_mode defaults it to filtered (whole-policy replace)", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ url_allowlist: ["https://api.github.com/*"] }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect((call[1] as { response_mode: string }).response_mode).toBe("filtered");
    });

    it("PUT rejects an invalid env var name", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ env_allowlist: ["1BAD"] }),
      });
      expect(res.status).toBe(400);
    });

    it("PUT rejects an invalid response_mode", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ response_mode: "raw" }),
      });
      expect(res.status).toBe(400);
    });

    it("PUT rejects an invalid response header name", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ response_header_allowlist: ["Bad: Header"] }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("mcp-server config routes", () => {
    it("GET returns null when no config is set", async () => {
      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "GET",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toBeNull();
    });

    it("PUT sets a stdio config", async () => {
      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          server_name: "github-mcp",
          transport: "stdio",
          command: "node",
          args: ["server.js"],
          env_var: "GITHUB_TOKEN",
        }),
      });
      expect(res.status).toBe(200);
      const call = engine.setMcpServerConfig.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      expect((call[1] as { server_name: string }).server_name).toBe("github-mcp");
    });

    it("PUT rejects a stdio config without env_var", async () => {
      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          server_name: "github-mcp",
          transport: "stdio",
          command: "node",
        }),
      });
      expect(res.status).toBe(400);
    });

    it("PUT rejects an http config without url", async () => {
      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ server_name: "remote", transport: "http" }),
      });
      expect(res.status).toBe(400);
    });

    it("DELETE removes the config", async () => {
      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.deleted).toBe(true);
      expect(engine.deleteMcpServerConfig).toHaveBeenCalledWith("secret://test-key");
    });
  });

  describe("connection-config routes", () => {
    it("GET returns null when no config is set", async () => {
      const res = await app.request("/api/v1/secrets/test-key/connection-config", {
        method: "GET",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toBeNull();
    });

    it("PUT sets a database + ssh config", async () => {
      const res = await app.request("/api/v1/secrets/test-key/connection-config", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          database: { tls_mode: "require" },
          ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAA"] },
        }),
      });
      expect(res.status).toBe(200);
      const call = engine.setConnectionConfig.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
    });

    it("PUT rejects an empty config", async () => {
      const res = await app.request("/api/v1/secrets/test-key/connection-config", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    });

    it("DELETE removes the config", async () => {
      const res = await app.request("/api/v1/secrets/test-key/connection-config", {
        method: "DELETE",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.deleted).toBe(true);
      expect(engine.deleteConnectionConfig).toHaveBeenCalledWith("secret://test-key");
    });
  });

  describe("POST /api/v1/secrets create validation", () => {
    it("rejects non-numeric expires_at", async () => {
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "new-key", type: "api_key", expires_at: "never" }),
      });
      expect(res.status).toBe(400);
    });

    it("accepts valid numeric expires_at", async () => {
      const res = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          name: "new-key",
          type: "api_key",
          expires_at: Date.now() + 86400000,
        }),
      });
      expect(res.status).toBe(201);
    });
  });

  describe("scope enforcement", () => {
    it("admin scope grants access to all operations", async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["admin"] });

      const res = await app.request("/api/v1/secrets", { headers: AUTH });
      expect(res.status).toBe(200);

      const res2 = await app.request("/api/v1/secrets", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ name: "k", type: "api_key" }),
      });
      expect(res2.status).toBe(201);
    });
  });
});
