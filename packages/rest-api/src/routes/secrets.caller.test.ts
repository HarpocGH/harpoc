import { describe, it, expect, beforeEach } from "vitest";
import type { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import {
  AUTH,
  EXPECTED_CALLER,
  FULL_POLICY,
  MOCK_TOKEN,
  buildSecretsApp,
  createMockEngine,
} from "./__fixtures__/secrets-app.js";

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = buildSecretsApp(engine);
});

describe("engine-level policy enforcement wiring (thesis §4.6)", () => {
  const JSON_HEADERS = { ...AUTH, "content-type": "application/json" };

  it("GET /:handle passes the token-derived caller to getSecretInfo", async () => {
    await app.request("/api/v1/secrets/test-key", { headers: AUTH });
    expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://test-key", EXPECTED_CALLER);
  });

  it("GET /:handle/value passes the caller to getSecretValue", async () => {
    await app.request("/api/v1/secrets/test-key/value", { headers: AUTH });
    expect(engine.getSecretValue).toHaveBeenCalledWith("secret://test-key", EXPECTED_CALLER);
  });

  it("DELETE /:handle passes the caller to revokeSecret", async () => {
    await app.request("/api/v1/secrets/test-key?confirm=true", {
      method: "DELETE",
      headers: AUTH,
    });
    expect(engine.revokeSecret).toHaveBeenCalledWith("secret://test-key", EXPECTED_CALLER);
  });

  it("POST /:handle/rotate passes the caller to rotateSecret", async () => {
    await app.request("/api/v1/secrets/test-key/rotate", {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/json" },
      body: JSON.stringify({ value: Buffer.from("new").toString("base64") }),
    });
    expect(engine.rotateSecret).toHaveBeenCalledWith(
      "secret://test-key",
      expect.any(Uint8Array),
      EXPECTED_CALLER,
    );
  });

  it("POST /:handle/use passes the caller to useSecret", async () => {
    await app.request("/api/v1/secrets/test-key/use", {
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
    expect(engine.useSecret).toHaveBeenCalledWith(
      "secret://test-key",
      expect.objectContaining({ type: "http" }),
      EXPECTED_CALLER,
    );
  });

  it("a project-scoped token derives a caller carrying the project claim", async () => {
    engine.verifyToken.mockReturnValue({ ...MOCK_TOKEN, project: "myproj" });
    await app.request("/api/v1/secrets/myproj%2Ftest-key", { headers: AUTH });
    expect(engine.getSecretInfo).toHaveBeenCalledWith("secret://myproj/test-key", {
      ...EXPECTED_CALLER,
      project: "myproj",
    });
  });

  it("an engine ACCESS_DENIED policy denial maps to 403", async () => {
    engine.getSecretValue.mockRejectedValue(
      VaultError.accessDenied("Principal lacks 'read' permission on this secret"),
    );
    const res = await app.request("/api/v1/secrets/test-key/value", { headers: AUTH });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.ACCESS_DENIED);
  });

  it("an engine SECRET_NOT_FOUND on a policy-concealed refusal maps to 404 like an unknown handle (R5)", async () => {
    engine.getSecretValue.mockRejectedValue(VaultError.secretNotFound("secret://test-key"));
    const res = await app.request("/api/v1/secrets/test-key/value", { headers: AUTH });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(body.message).toBe("Secret not found: secret://test-key");
  });

  // W1: the secret-scoped configuration routes sat outside the policy layer —
  // a policy-denied-rotate principal could still rewrite the allowlists.
  const configCallerCases: {
    title: string;
    engineFn: keyof typeof engine;
    request: () => Response | Promise<Response>;
    args: unknown[];
  }[] = [
    {
      title: "GET /:handle/injection-policy",
      engineFn: "getInjectionPolicy",
      request: () => app.request("/api/v1/secrets/test-key/injection-policy", { headers: AUTH }),
      args: ["secret://test-key", EXPECTED_CALLER],
    },
    {
      title: "PUT /:handle/injection-policy",
      engineFn: "setInjectionPolicy",
      request: () =>
        app.request("/api/v1/secrets/test-key/injection-policy", {
          method: "PUT",
          headers: JSON_HEADERS,
          body: JSON.stringify(FULL_POLICY),
        }),
      args: [
        "secret://test-key",
        expect.objectContaining({ url_allowlist: FULL_POLICY.url_allowlist }),
        expect.anything(),
        EXPECTED_CALLER,
      ],
    },
    {
      title: "GET /:handle/mcp-server",
      engineFn: "getMcpServerConfig",
      request: () => app.request("/api/v1/secrets/test-key/mcp-server", { headers: AUTH }),
      args: ["secret://test-key", EXPECTED_CALLER],
    },
    {
      title: "PUT /:handle/mcp-server",
      engineFn: "setMcpServerConfig",
      request: () =>
        app.request("/api/v1/secrets/test-key/mcp-server", {
          method: "PUT",
          headers: JSON_HEADERS,
          body: JSON.stringify({
            server_name: "docs",
            transport: "http",
            url: "https://mcp.example.com/mcp",
          }),
        }),
      args: [
        "secret://test-key",
        expect.objectContaining({ server_name: "docs" }),
        EXPECTED_CALLER,
      ],
    },
    {
      title: "DELETE /:handle/mcp-server",
      engineFn: "deleteMcpServerConfig",
      request: () =>
        app.request("/api/v1/secrets/test-key/mcp-server", { method: "DELETE", headers: AUTH }),
      args: ["secret://test-key", EXPECTED_CALLER],
    },
    {
      title: "GET /:handle/connection-config",
      engineFn: "getConnectionConfig",
      request: () => app.request("/api/v1/secrets/test-key/connection-config", { headers: AUTH }),
      args: ["secret://test-key", EXPECTED_CALLER],
    },
    {
      title: "PUT /:handle/connection-config",
      engineFn: "setConnectionConfig",
      request: () =>
        app.request("/api/v1/secrets/test-key/connection-config", {
          method: "PUT",
          headers: JSON_HEADERS,
          body: JSON.stringify({ database: { tls_mode: "require" } }),
        }),
      args: [
        "secret://test-key",
        expect.objectContaining({ database: expect.anything() }),
        EXPECTED_CALLER,
      ],
    },
    {
      title: "DELETE /:handle/connection-config",
      engineFn: "deleteConnectionConfig",
      request: () =>
        app.request("/api/v1/secrets/test-key/connection-config", {
          method: "DELETE",
          headers: AUTH,
        }),
      args: ["secret://test-key", EXPECTED_CALLER],
    },
  ];

  for (const tc of configCallerCases) {
    it(`${tc.title} passes the token-derived caller to ${String(tc.engineFn)}`, async () => {
      await tc.request();
      expect(engine[tc.engineFn]).toHaveBeenCalledWith(...tc.args);
    });
  }

  it("a config-route ACCESS_DENIED maps to 403", async () => {
    engine.setInjectionPolicy.mockRejectedValue(
      VaultError.accessDenied("Principal lacks 'admin' permission on this secret"),
    );
    const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
      method: "PUT",
      headers: JSON_HEADERS,
      body: JSON.stringify(FULL_POLICY),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe(ErrorCode.ACCESS_DENIED);
  });
});
