import { describe, it, expect, beforeEach } from "vitest";
import type { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import {
  AUTH,
  FULL_POLICY,
  buildSecretsApp,
  createMockEngine,
} from "./__fixtures__/secrets-app.js";

let app: Hono<HarpocEnv>;
let engine: ReturnType<typeof createMockEngine>;

beforeEach(() => {
  engine = createMockEngine();
  app = buildSecretsApp(engine);
});

describe("secret routes", () => {
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
        network_isolation: false,
      });
    });

    it("PUT sets the policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify(FULL_POLICY),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      expect((call[1] as { command_allowlist: string[] }).command_allowlist).toEqual(["gh"]);
      const policy = call[1] as { response_mode: string; response_header_allowlist: string[] };
      expect(policy.response_mode).toBe("status_only");
      expect(policy.response_header_allowlist).toEqual(["Content-Type"]);
    });

    it.each(Object.keys(FULL_POLICY))(
      "PUT omitting %s is a 400 naming the field, engine untouched (R3)",
      async (field) => {
        const partial = Object.fromEntries(
          Object.entries(FULL_POLICY).filter(([key]) => key !== field),
        );
        const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
          method: "PUT",
          headers: { ...AUTH, "content-type": "application/json" },
          body: JSON.stringify(partial),
        });
        expect(res.status).toBe(400);
        const body = (await res.json()) as { error: string; message: string };
        expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
        if (field === "response_mode") {
          expect(body.message).toContain(
            "response_mode: must be one of full, filtered, status_only",
          );
        } else {
          expect(body.message).toContain(`${field}: Invalid input: expected `);
          expect(body.message).toContain("received undefined");
        }
        expect(engine.setInjectionPolicy).not.toHaveBeenCalled();
      },
    );

    it("PUT with an unknown key is a 400 naming it, engine untouched (R10/A5)", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, fs_isolaton: true }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string; message: string };
      expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
      expect(body.message).toContain('Unrecognized key: "fs_isolaton"');
      expect(engine.setInjectionPolicy).not.toHaveBeenCalled();
    });

    it("PUT forwards network_isolation: true to the engine", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, network_isolation: true }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect((call[1] as { network_isolation: boolean }).network_isolation).toBe(true);
    });

    it("PUT forwards fs_isolation: true to the engine", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, fs_isolation: true }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect((call[1] as { fs_isolation: boolean }).fs_isolation).toBe(true);
    });

    it("PUT rejects a non-boolean fs_isolation", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, fs_isolation: "yes" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { message: string };
      expect(body.message).toContain("fs_isolation:");
    });

    it("GET returns fs_isolation", async () => {
      engine.getInjectionPolicy.mockResolvedValueOnce({
        url_allowlist: [],
        command_allowlist: ["gh"],
        env_allowlist: [],
        host_allowlist: [],
        response_mode: "filtered",
        response_header_allowlist: [],
        network_isolation: false,
        fs_isolation: true,
      });
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "GET",
        headers: AUTH,
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.fs_isolation).toBe(true);
    });

    it("PUT rejects a non-boolean network_isolation", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, network_isolation: "yes" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { message: string };
      expect(body.message).toContain("network_isolation:");
    });

    it("PUT rejects an invalid env var name", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, env_allowlist: ["1BAD"] }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { message: string };
      expect(body.message).toContain("env_allowlist.0:");
    });

    it("PUT rejects an invalid response_mode", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, response_mode: "raw" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { message: string };
      expect(body.message).toContain("response_mode:");
    });

    it("PUT rejects an invalid response header name", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, response_header_allowlist: ["Bad: Header"] }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { message: string };
      expect(body.message).toContain("response_header_allowlist.0:");
    });

    it("PUT passes the interpreter acknowledgement to the engine, not the policy", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, acknowledge_interpreters: true }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect((call[1] as Record<string, unknown>).acknowledge_interpreters).toBeUndefined();
      expect(call[2]).toEqual({ acknowledge_interpreters: true });
    });

    it("PUT defaults the interpreter acknowledgement to false", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify(FULL_POLICY),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect(call[2]).toEqual({ acknowledge_interpreters: false });
    });

    it("PUT rejects a non-boolean acknowledge_interpreters", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, acknowledge_interpreters: "yes" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { message: string };
      expect(body.message).toContain("acknowledge_interpreters:");
    });

    it("PUT maps an unacknowledged interpreter refusal to 400", async () => {
      engine.setInjectionPolicy.mockRejectedValueOnce(
        VaultError.interpreterNotAcknowledged(["python"]),
      );
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, command_allowlist: ["python"] }),
      });
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe(ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED);
    });

    // R3: smtp_recipient_allowlist / imap_read_only follow the same rule as
    // every other policy field — the PUT body is the whole policy, so each is
    // required and a body omitting one is a 400 naming it (the it.each
    // omission table above), never a silent reset to a default.
    it("PUT forwards smtp_recipient_allowlist to the engine", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          ...FULL_POLICY,
          smtp_recipient_allowlist: ["ops@example.com", "*@example.com"],
        }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect((call[1] as { smtp_recipient_allowlist: string[] }).smtp_recipient_allowlist).toEqual([
        "ops@example.com",
        "*@example.com",
      ]);
    });

    it("PUT forwards imap_read_only: true to the engine", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, imap_read_only: true }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect((call[1] as { imap_read_only: boolean }).imap_read_only).toBe(true);
    });

    it("PUT forwards strict_tree_exit: true to the engine (2026-09-10)", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({ ...FULL_POLICY, strict_tree_exit: true }),
      });
      expect(res.status).toBe(200);
      const call = engine.setInjectionPolicy.mock.calls[0] as unknown[];
      expect((call[1] as { strict_tree_exit: boolean }).strict_tree_exit).toBe(true);
    });

    it("PUT rejects a malformed recipient pattern with SCHEMA_VALIDATION_ERROR", async () => {
      const res = await app.request("/api/v1/secrets/test-key/injection-policy", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          ...FULL_POLICY,
          smtp_recipient_allowlist: ["not-a-valid-pattern"],
        }),
      });
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
      expect(body.message).toContain("smtp_recipient_allowlist.0:");
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

    it("PUT carries an explicit protocol through to the engine", async () => {
      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          server_name: "remote",
          transport: "http",
          url: "https://mcp.example.com/mcp",
          protocol: "2026-07-28",
        }),
      });
      expect(res.status).toBe(200);
      const call = engine.setMcpServerConfig.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      expect(call[1]).toMatchObject({ protocol: "2026-07-28" });
    });

    it("PUT without protocol reaches the engine with the default revision", async () => {
      const res = await app.request("/api/v1/secrets/test-key/mcp-server", {
        method: "PUT",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          server_name: "remote",
          transport: "http",
          url: "https://mcp.example.com/mcp",
        }),
      });
      expect(res.status).toBe(200);
      const call = engine.setMcpServerConfig.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      expect(call[1]).toMatchObject({ protocol: "2025-11-25" });
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
      expect(engine.deleteMcpServerConfig).toHaveBeenCalledWith(
        "secret://test-key",
        expect.objectContaining({ principal_id: "test-agent" }),
      );
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
      expect(engine.deleteConnectionConfig).toHaveBeenCalledWith(
        "secret://test-key",
        expect.objectContaining({ principal_id: "test-agent" }),
      );
    });
  });
});
