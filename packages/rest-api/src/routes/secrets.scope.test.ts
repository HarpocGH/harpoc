import { describe, it, expect, beforeEach } from "vitest";
import type { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { AUTH, MOCK_TOKEN, buildSecretsApp, createMockEngine } from "./__fixtures__/secrets-app.js";

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = buildSecretsApp(engine);
});

describe("secret routes", () => {
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

  describe("scope denial on sensitive routes", () => {
    const JSON_HEADERS = { ...AUTH, "content-type": "application/json" };
    const withoutScope = (missing: string) =>
      MOCK_TOKEN.scope.filter((s) => s !== missing && s !== "admin");

    const cases: {
      title: string;
      missing: string;
      engineFn: keyof ReturnType<typeof createMockEngine>;
      request: () => Response | Promise<Response>;
    }[] = [
      {
        title: "GET /:handle requires read",
        missing: "read",
        engineFn: "getSecretInfo",
        request: () => app.request("/api/v1/secrets/test-key", { headers: AUTH }),
      },
      {
        title: "GET /:handle/value requires read",
        missing: "read",
        engineFn: "getSecretValue",
        request: () => app.request("/api/v1/secrets/test-key/value", { headers: AUTH }),
      },
      {
        title: "POST /:handle/rotate requires rotate",
        missing: "rotate",
        engineFn: "rotateSecret",
        request: () =>
          app.request("/api/v1/secrets/test-key/rotate", {
            method: "POST",
            headers: JSON_HEADERS,
            body: JSON.stringify({ value: Buffer.from("new").toString("base64") }),
          }),
      },
      {
        title: "POST /:handle/use requires use",
        missing: "use",
        engineFn: "useSecret",
        request: () =>
          app.request("/api/v1/secrets/test-key/use", {
            method: "POST",
            headers: JSON_HEADERS,
            body: JSON.stringify({
              action: {
                type: "http",
                method: "GET",
                url: "https://api.example.com/data",
                injection: { type: "bearer" },
              },
            }),
          }),
      },
      {
        title: "GET /:handle/injection-policy requires read",
        missing: "read",
        engineFn: "getInjectionPolicy",
        request: () => app.request("/api/v1/secrets/test-key/injection-policy", { headers: AUTH }),
      },
      {
        title: "PUT /:handle/injection-policy requires admin",
        missing: "admin",
        engineFn: "setInjectionPolicy",
        request: () =>
          app.request("/api/v1/secrets/test-key/injection-policy", {
            method: "PUT",
            headers: JSON_HEADERS,
            body: JSON.stringify({ url_allowlist: ["https://api.example.com/*"] }),
          }),
      },
      {
        title: "GET /:handle/mcp-server requires read",
        missing: "read",
        engineFn: "getMcpServerConfig",
        request: () => app.request("/api/v1/secrets/test-key/mcp-server", { headers: AUTH }),
      },
      {
        title: "PUT /:handle/mcp-server requires rotate",
        missing: "rotate",
        engineFn: "setMcpServerConfig",
        request: () =>
          app.request("/api/v1/secrets/test-key/mcp-server", {
            method: "PUT",
            headers: JSON_HEADERS,
            body: JSON.stringify({}),
          }),
      },
      {
        title: "DELETE /:handle/mcp-server requires rotate",
        missing: "rotate",
        engineFn: "deleteMcpServerConfig",
        request: () =>
          app.request("/api/v1/secrets/test-key/mcp-server", { method: "DELETE", headers: AUTH }),
      },
      {
        title: "GET /:handle/connection-config requires read",
        missing: "read",
        engineFn: "getConnectionConfig",
        request: () => app.request("/api/v1/secrets/test-key/connection-config", { headers: AUTH }),
      },
      {
        title: "PUT /:handle/connection-config requires rotate",
        missing: "rotate",
        engineFn: "setConnectionConfig",
        request: () =>
          app.request("/api/v1/secrets/test-key/connection-config", {
            method: "PUT",
            headers: JSON_HEADERS,
            body: JSON.stringify({}),
          }),
      },
      {
        title: "DELETE /:handle/connection-config requires rotate",
        missing: "rotate",
        engineFn: "deleteConnectionConfig",
        request: () =>
          app.request("/api/v1/secrets/test-key/connection-config", {
            method: "DELETE",
            headers: AUTH,
          }),
      },
    ];

    for (const tc of cases) {
      it(`${tc.title} (403, engine untouched)`, async () => {
        engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: withoutScope(tc.missing) });
        const res = await tc.request();
        expect(res.status).toBe(403);
        expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
        expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
        expect(engine.auditScopeRefusal).toHaveBeenCalledWith(
          expect.objectContaining({ principal_id: MOCK_TOKEN.sub, interface: "rest" }),
          expect.stringMatching(/^(GET|POST|PUT|DELETE) \/api\/v1\/secrets/),
          "permission",
        );
        expect(engine[tc.engineFn]).not.toHaveBeenCalled();
      });
    }

    const patternCases: {
      title: string;
      engineFn: keyof ReturnType<typeof createMockEngine>;
      request: () => Response | Promise<Response>;
    }[] = [
      {
        title: "GET /:handle/value",
        engineFn: "getSecretValue",
        request: () => app.request("/api/v1/secrets/test-key/value", { headers: AUTH }),
      },
      {
        title: "POST /:handle/use",
        engineFn: "useSecret",
        request: () =>
          app.request("/api/v1/secrets/test-key/use", {
            method: "POST",
            headers: JSON_HEADERS,
            body: JSON.stringify({
              action: {
                type: "http",
                method: "GET",
                url: "https://api.example.com/data",
                injection: { type: "bearer" },
              },
            }),
          }),
      },
      {
        title: "PUT /:handle/injection-policy",
        engineFn: "setInjectionPolicy",
        request: () =>
          app.request("/api/v1/secrets/test-key/injection-policy", {
            method: "PUT",
            headers: JSON_HEADERS,
            body: JSON.stringify({ url_allowlist: ["https://api.example.com/*"] }),
          }),
      },
      {
        title: "PUT /:handle/mcp-server",
        engineFn: "setMcpServerConfig",
        request: () =>
          app.request("/api/v1/secrets/test-key/mcp-server", {
            method: "PUT",
            headers: JSON_HEADERS,
            body: JSON.stringify({}),
          }),
      },
      {
        title: "PUT /:handle/connection-config",
        engineFn: "setConnectionConfig",
        request: () =>
          app.request("/api/v1/secrets/test-key/connection-config", {
            method: "PUT",
            headers: JSON_HEADERS,
            body: JSON.stringify({}),
          }),
      },
    ];

    for (const tc of patternCases) {
      it(`${tc.title} enforces token name patterns (403, engine untouched)`, async () => {
        engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, secrets: ["db-*"] });
        const res = await tc.request();
        expect(res.status).toBe(403);
        expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.ACCESS_DENIED);
        expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
        expect(engine.auditScopeRefusal).toHaveBeenCalledWith(
          expect.objectContaining({ principal_id: MOCK_TOKEN.sub, interface: "rest" }),
          expect.stringMatching(/^(GET|POST|PUT|DELETE) \/api\/v1\/secrets/),
          "secret",
        );
        expect(engine[tc.engineFn]).not.toHaveBeenCalled();
      });
    }
  });

  /**
   * R14/D6: both endpoint-configuration writes take `rotate`, not `admin`.
   * The denial table above only proves that a token *missing* `rotate` is
   * refused — a route re-gated on `admin` would satisfy it too. This is the
   * other half, and the only place the tree states the endpoint scope
   * positively.
   */
  describe("a rotate-only token completes both configuration writes (R14/D6)", () => {
    const ROTATE_CALLER = {
      principal_type: "agent",
      principal_id: "test-agent",
      interface: "rest",
    };

    const cases: {
      title: string;
      path: string;
      engineFn: keyof ReturnType<typeof createMockEngine>;
      body: Record<string, unknown>;
    }[] = [
      {
        title: "PUT /:handle/mcp-server",
        path: "mcp-server",
        engineFn: "setMcpServerConfig",
        body: {
          server_name: "github-mcp",
          transport: "stdio",
          protocol: "2025-11-25",
          command: "node",
          args: ["server.js"],
          env_var: "GITHUB_TOKEN",
        },
      },
      {
        title: "PUT /:handle/connection-config",
        path: "connection-config",
        engineFn: "setConnectionConfig",
        body: { database: { tls_mode: "require" } },
      },
    ];

    for (const tc of cases) {
      it(`${tc.title} succeeds on scope ["rotate"] and the engine setter is called`, async () => {
        engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["rotate"] });

        const res = await app.request(`/api/v1/secrets/test-key/${tc.path}`, {
          method: "PUT",
          headers: { ...AUTH, "content-type": "application/json" },
          body: JSON.stringify(tc.body),
        });

        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ data: { updated: true } });
        // No `admin_scope` on the caller: the rotate-only token is not the
        // admin-user class, so this is the endpoint scope alone.
        expect(engine[tc.engineFn]).toHaveBeenCalledWith(
          "secret://test-key",
          tc.body,
          ROTATE_CALLER,
        );
      });
    }

    it('DELETE /:handle/connection-config succeeds on scope ["rotate"] and the engine deleter is called', async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["rotate"] });

      const res = await app.request("/api/v1/secrets/test-key/connection-config", {
        method: "DELETE",
        headers: AUTH,
      });

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ data: { deleted: true } });
      expect(engine.deleteConnectionConfig).toHaveBeenCalledWith(
        "secret://test-key",
        ROTATE_CALLER,
      );
    });

    it('DELETE /:handle/mcp-server succeeds on scope ["rotate"] and the engine deleter is called', async () => {
      engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["rotate"] });

      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "DELETE",
        headers: AUTH,
      });

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ data: { deleted: true } });
      expect(engine.deleteMcpServerConfig).toHaveBeenCalledWith("secret://test-key", ROTATE_CALLER);
    });
  });
});

// H4 + the untested project dimension of checkTokenScope: `?project=` arrives as
// the empty string, which is falsy but not nullish — it skipped the cross-project
// check and then survived `??`, so the engine was asked for every project.
describe("GET /secrets — project scope", () => {
  it("an empty ?project= does not widen a project-scoped token to the whole vault", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "myproj" });
    const res = await app.request("/api/v1/secrets?project=", { headers: AUTH });
    expect(res.status).toBe(200);
    expect(engine.listSecrets).toHaveBeenCalledWith("myproj", expect.anything());
  });

  it("a whitespace-free absent parameter behaves identically", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "myproj" });
    await app.request("/api/v1/secrets", { headers: AUTH });
    expect(engine.listSecrets).toHaveBeenCalledWith("myproj", expect.anything());
  });

  it("refuses an explicit cross-project request (403, engine untouched)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "myproj" });
    const res = await app.request("/api/v1/secrets?project=other", { headers: AUTH });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.ACCESS_DENIED);
    expect(engine.listSecrets).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).toHaveBeenCalledWith(
      expect.objectContaining({ project: "myproj", interface: "rest" }),
      "GET /api/v1/secrets",
      "project",
    );
  });

  it("honours the token's own project when it matches", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "myproj" });
    const res = await app.request("/api/v1/secrets?project=myproj", { headers: AUTH });
    expect(res.status).toBe(200);
    expect(engine.listSecrets).toHaveBeenCalledWith("myproj", expect.anything());
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });

  it("a scope refusal on a sealed vault answers 503 VAULT_LOCKED (the writer re-enters assertUnlocked)", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, scope: ["list"] });
    engine.auditScopeRefusal.mockImplementation(() => {
      throw VaultError.vaultLocked();
    });
    const res = await app.request("/api/v1/secrets", {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.VAULT_LOCKED);
  });

  it("negative control: an unscoped token may still request a project", async () => {
    const res = await app.request("/api/v1/secrets?project=anything", { headers: AUTH });
    expect(res.status).toBe(200);
    expect(engine.listSecrets).toHaveBeenCalledWith("anything", expect.anything());
  });

  it("negative control: an unscoped token with no parameter lists everything", async () => {
    await app.request("/api/v1/secrets", { headers: AUTH });
    expect(engine.listSecrets).toHaveBeenCalledWith(undefined, expect.anything());
  });
});
