import { describe, it, expect, beforeEach } from "vitest";
import type { Hono } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import {
  AUTH,
  NON_OBJECT_BODIES,
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

    // v1.3: the action union widened to 11 types purely through the shared
    // schema (useSecretActionSchema) — no REST-side copy of the union exists
    // to update. A websocket action (unknown to REST before this tranche)
    // must parse, reach the engine verbatim and round-trip its typed result
    // without any route change; that is the pin.
    it("executes a websocket action and returns the collected messages (v1.3 context widening)", async () => {
      engine.useSecret.mockResolvedValueOnce({
        type: "websocket",
        messages: ["hello from server"],
        close_code: 1000,
      });
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: {
            type: "websocket",
            url: "wss://echo.example.com/socket",
            injection: { type: "bearer" },
            message: "ping",
          },
        }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.type).toBe("websocket");
      expect(body.data.messages).toEqual(["hello from server"]);
      expect(body.data.close_code).toBe(1000);

      const call = engine.useSecret.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      const action = call[1] as { type: string; url: string; message?: string };
      expect(action.type).toBe("websocket");
      expect(action.url).toBe("wss://echo.example.com/socket");
      expect(action.message).toBe("ping");
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

    it("POST /use refuses a stray top-level key beside action (R10/A5)", async () => {
      const res = await app.request("/api/v1/secrets/test-key/use", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: JSON.stringify({
          action: {
            type: "http",
            method: "GET",
            url: "https://api.example.com/x",
            injection: { type: "bearer" },
          },
          handle: "secret://other",
        }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string; message: string };
      expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
      expect(body.message).toContain('Unrecognized key: "handle"');
      expect(engine.useSecret).not.toHaveBeenCalled();
    });

    it.each(NON_OBJECT_BODIES)(
      "refuses %s body with the framing message and never reaches the engine",
      async (_kind, raw) => {
        const res = await app.request("/api/v1/secrets/test-key/use", {
          method: "POST",
          headers: { ...AUTH, "content-type": "application/json" },
          body: raw,
        });
        expect(res.status).toBe(400);
        const body = (await res.json()) as { error: string; message: string };
        expect(body.error).toBe(ErrorCode.SCHEMA_VALIDATION_ERROR);
        expect(body.message).toBe("Request body must be valid JSON");
        expect(engine.useSecret).not.toHaveBeenCalled();
      },
    );
  });
});

function postUse(action: Record<string, unknown>): Response | Promise<Response> {
  return app.request("/api/v1/secrets/test-key/use", {
    method: "POST",
    headers: { ...AUTH, "content-type": "application/json" },
    body: JSON.stringify({ action }),
  });
}

type ContextRow = [
  string,
  Record<string, unknown>,
  Record<string, unknown>,
  Record<string, unknown>,
];

// I13 (test-review-2026-10-09): each v1.3 context's valid action posted to the
// use route reaches the engine as the parsed action — every schema default
// spelled out — and the engine's result comes back as `{ data }`. Hosts and
// URLs are loopback literals; the engine is a mock, nothing connects.
const V13_CONTEXTS: ContextRow[] = [
  [
    "smtp",
    {
      type: "smtp",
      host: "127.0.0.1",
      from: "agent@example.com",
      to: ["ops@example.com"],
      subject: "Nightly report",
      text: "All green",
    },
    {
      type: "smtp",
      host: "127.0.0.1",
      security: "tls",
      from: "agent@example.com",
      to: ["ops@example.com"],
      subject: "Nightly report",
      text: "All green",
    },
    { type: "smtp", accepted: 1, message_id: "<report-1@harpoc.local>" },
  ],
  [
    "imap",
    { type: "imap", host: "127.0.0.1", operation: { kind: "search", unseen: true } },
    {
      type: "imap",
      host: "127.0.0.1",
      port: 993,
      mailbox: "INBOX",
      operation: { kind: "search", unseen: true },
    },
    { type: "imap", operation: "search", uids: [3, 7] },
  ],
  [
    "websocket",
    {
      type: "websocket",
      url: "wss://127.0.0.1/socket",
      injection: { type: "bearer" },
      message: "ping",
      collect: { max_messages: 2 },
    },
    {
      type: "websocket",
      url: "wss://127.0.0.1/socket",
      injection: { type: "bearer" },
      message: "ping",
      collect: { max_messages: 2, window_ms: 30_000 },
    },
    { type: "websocket", messages: ["pong", "done"], close_code: 1000 },
  ],
  [
    "sftp",
    {
      type: "sftp",
      host: "127.0.0.1",
      user: "deploy",
      operation: "download",
      remote_path: "/srv/reports/daily.csv",
      local_path: "/var/harpoc/daily.csv",
    },
    {
      type: "sftp",
      host: "127.0.0.1",
      user: "deploy",
      operation: "download",
      remote_path: "/srv/reports/daily.csv",
      local_path: "/var/harpoc/daily.csv",
    },
    { type: "sftp", exit_code: 0, stdout: "", stderr: "" },
  ],
  [
    "docker_registry",
    { type: "docker_registry", operation: "pull", image: "127.0.0.1:5000/team/app:1.2.0" },
    {
      type: "docker_registry",
      operation: "pull",
      image: "127.0.0.1:5000/team/app:1.2.0",
      timeout_ms: 300_000,
    },
    {
      type: "docker_registry",
      operation: "pull",
      exit_code: 0,
      stdout: "1.2.0: Pulling from team/app",
      stderr: "",
    },
  ],
];

describe("POST /api/v1/secrets/:handle/use — the v1.3 contexts reach the engine (I13)", () => {
  it.each(V13_CONTEXTS)(
    "%s: the parsed action reaches useSecret whole and the result returns as data",
    async (_type, action, parsed, result) => {
      engine.useSecret.mockResolvedValueOnce(result);
      const res = await postUse(action);
      expect(res.status).toBe(200);
      expect(await res.json()).toStrictEqual({ data: result });
      expect(engine.useSecret).toHaveBeenCalledTimes(1);
      const call = engine.useSecret.mock.calls[0] as unknown[];
      expect(call[0]).toBe("secret://test-key");
      expect(call[1]).toStrictEqual(parsed);
    },
  );
});

// I15 (test-review-2026-10-09): a per-invocation response_mode looser than the
// secret's policy is refused by the engine before any request executes; the
// route renders the refusal as 403 with the error body, and the engine's one
// useSecret call is all that ran.
describe("POST /api/v1/secrets/:handle/use — a loosened response_mode (I15)", () => {
  it("maps the engine's RESPONSE_MODE_NOT_ALLOWED to 403 with the error body, nothing else run", async () => {
    const action = {
      type: "http",
      method: "GET",
      url: "https://127.0.0.1/data",
      injection: { type: "bearer" },
      response_mode: "full",
    };
    engine.useSecret.mockRejectedValueOnce(VaultError.responseModeNotAllowed("full", "filtered"));
    const res = await postUse(action);
    expect(res.status).toBe(403);
    expect(await res.json()).toStrictEqual({
      error: ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
      message:
        'Response mode "full" not allowed: secret policy is "filtered" and overrides may only tighten',
    });
    expect(engine.useSecret).toHaveBeenCalledTimes(1);
    expect((engine.useSecret.mock.calls[0] as unknown[])[1]).toStrictEqual(action);
    for (const [name, fn] of Object.entries(engine)) {
      if (name === "useSecret" || name === "verifyToken") continue;
      expect(fn, name).not.toHaveBeenCalled();
    }
  });
});
