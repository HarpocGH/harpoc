import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

// Token endpoint mock server
let tokenServer: Server;
let tokenServerUrl: string;
let tokenEndpointHandler: (req: IncomingMessage, res: ServerResponse) => void;

// Target HTTP server for useSecret
let targetServer: Server;
let targetServerUrl: string;

function defaultProviderConfig(overrides?: Partial<OAuthProviderConfig>): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: tokenServerUrl,
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "my-client-id",
    client_secret: "my-client-secret",
    scopes: ["repo", "user"],
    ...overrides,
  };
}

beforeAll(async () => {
  // Token endpoint
  tokenServer = createServer((req, res) => {
    tokenEndpointHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    tokenServer.listen(0, "127.0.0.1", () => resolve());
  });
  const tokenAddr = tokenServer.address() as { port: number };
  tokenServerUrl = `http://127.0.0.1:${tokenAddr.port}`;

  // Target server for useSecret
  targetServer = createServer((req, res) => {
    const auth = req.headers["authorization"] ?? "none";
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ authorization: auth, path: req.url }));
  });
  await new Promise<void>((resolve) => {
    targetServer.listen(0, "127.0.0.1", () => resolve());
  });
  const targetAddr = targetServer.address() as { port: number };
  targetServerUrl = `http://127.0.0.1:${targetAddr.port}`;
});

afterAll(() => {
  tokenServer.close();
  targetServer.close();
});

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-oauth-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });

  // Default token endpoint handler: return success
  tokenEndpointHandler = (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        access_token: "refreshed-access-token",
        refresh_token: "refreshed-refresh-token",
        expires_in: 3600,
      }),
    );
  };
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

// ---------------------------------------------------------------------------
// createOAuthSecret
// ---------------------------------------------------------------------------

describe("createOAuthSecret", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates a PENDING OAuth secret with provider configuration", async () => {
    const config = defaultProviderConfig();
    const { handle, secretId } = await engine.createOAuthSecret("github-token", config);

    expect(handle).toBe("secret://github-token");
    expect(secretId).toBeTruthy();

    const info = await engine.getSecretInfo("secret://github-token");
    expect(info.type).toBe("oauth_token");
    expect(info.status).toBe("pending");

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.provider).toBe("github");
    expect(status.has_access_token).toBe(false);
    expect(status.has_refresh_token).toBe(false);
    expect(status.refresh_status).toBe("no_refresh_token");
  });

  it("works without client_secret", async () => {
    const config = defaultProviderConfig({ client_secret: undefined });
    const { secretId } = await engine.createOAuthSecret("no-secret", config);

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.provider).toBe("github");
  });

  it("logs OAUTH_AUTHORIZE audit event", async () => {
    const config = defaultProviderConfig();
    await engine.createOAuthSecret("audit-test", config);

    const events = engine.queryAudit({ eventType: AuditEventType.OAUTH_AUTHORIZE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail).toMatchObject({
      provider: "github",
      grant_type: "authorization_code",
    });
  });
});

// ---------------------------------------------------------------------------
// completeOAuthFlow
// ---------------------------------------------------------------------------

describe("completeOAuthFlow", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    const result = await engine.createOAuthSecret("flow-test", defaultProviderConfig());
    secretId = result.secretId;
  });

  it("transitions secret to ACTIVE and stores encrypted tokens", async () => {
    const expiresAt = Date.now() + 3600_000;
    await engine.completeOAuthFlow(secretId, "access-tok-123", "refresh-tok-456", expiresAt);

    const info = await engine.getSecretInfo("secret://flow-test");
    expect(info.status).toBe("active");

    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("access-tok-123");

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.has_access_token).toBe(true);
    expect(status.has_refresh_token).toBe(true);
    expect(status.access_token_expires_at).toBe(expiresAt);
    expect(status.refresh_status).toBe("ok");
  });

  it("works without refresh token", async () => {
    await engine.completeOAuthFlow(secretId, "access-only");

    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("access-only");

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.has_access_token).toBe(true);
    expect(status.has_refresh_token).toBe(false);
    expect(status.refresh_status).toBe("no_refresh_token");
  });

  it("rejects non-existent secrets", async () => {
    await expect(
      engine.completeOAuthFlow("non-existent-id", "token"),
    ).rejects.toMatchObject({ code: ErrorCode.SECRET_NOT_FOUND });
  });

  it("rejects non-OAuth secrets", async () => {
    await engine.createSecret({
      name: "api-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });
    const apiKeyId = await engine.resolveSecretId("secret://api-key");

    await expect(
      engine.completeOAuthFlow(apiKeyId, "token"),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_NOT_CONFIGURED });
  });

  it("logs OAUTH_CALLBACK audit event", async () => {
    await engine.completeOAuthFlow(secretId, "tok", "refresh");

    const events = engine.queryAudit({ eventType: AuditEventType.OAUTH_CALLBACK });
    expect(events.length).toBe(1);
    expect(events[0]?.detail).toMatchObject({ has_refresh_token: true });
  });
});

// ---------------------------------------------------------------------------
// refreshOAuthToken
// ---------------------------------------------------------------------------

describe("refreshOAuthToken", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    const result = await engine.createOAuthSecret("refresh-test", defaultProviderConfig());
    secretId = result.secretId;
  });

  it("refreshes token via token endpoint", async () => {
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);

    const newExpiry = await engine.refreshOAuthToken(secretId);
    expect(newExpiry).toBeGreaterThan(Date.now());

    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("refreshed-access-token");
  });

  it("stores new refresh token if returned by endpoint", async () => {
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);
    await engine.refreshOAuthToken(secretId);

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.has_refresh_token).toBe(true);
  });

  it("rejects when no refresh token is available", async () => {
    await engine.completeOAuthFlow(secretId, "access-only");

    await expect(engine.refreshOAuthToken(secretId)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_REFRESH_FAILED,
    });
  });

  it("rejects when token endpoint returns error", async () => {
    tokenEndpointHandler = (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    };

    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);

    await expect(engine.refreshOAuthToken(secretId)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_REFRESH_FAILED,
    });
  });

  it("logs OAUTH_REFRESH audit event", async () => {
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);
    await engine.refreshOAuthToken(secretId);

    const events = engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH });
    expect(events.length).toBe(1);
    expect(events[0]?.detail).toHaveProperty("new_expires_at");
  });

  it("audits a failed refresh with success=false and the error code", async () => {
    tokenEndpointHandler = (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    };

    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);
    await expect(engine.refreshOAuthToken(secretId)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_REFRESH_FAILED,
    });

    const events = engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH });
    const denied = events.find((e) => e.success === false);
    expect(denied).toBeDefined();
    expect(denied?.secret_id).toBe(secretId);
    expect(denied?.detail).toMatchObject({
      action: "refresh",
      error: ErrorCode.OAUTH_REFRESH_FAILED,
    });
  });

  it("a successful refresh logs no success=false OAUTH_REFRESH event", async () => {
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);
    await engine.refreshOAuthToken(secretId);

    const events = engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH });
    expect(events.filter((e) => !e.success)).toHaveLength(0);
  });

  it("coalesces concurrent refreshes onto a single token-endpoint POST", async () => {
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);

    let hits = 0;
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    tokenEndpointHandler = (_req, res) => {
      hits++;
      void gate.then(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "coalesced-access-token",
            refresh_token: "rotated-refresh-token",
            expires_in: 3600,
          }),
        );
      });
    };

    const first = engine.refreshOAuthToken(secretId);
    const second = engine.refreshOAuthToken(secretId);
    release();
    const [expiryA, expiryB] = await Promise.all([first, second]);

    expect(hits).toBe(1);
    expect(expiryA).toBe(expiryB);
  });

  it("coalesces an on-use auto-refresh with an explicit refresh", async () => {
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);

    let hits = 0;
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    tokenEndpointHandler = (_req, res) => {
      hits++;
      void gate.then(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "coalesced-access-token",
            refresh_token: "rotated-refresh-token",
            expires_in: 3600,
          }),
        );
      });
    };

    const explicitRefresh = engine.refreshOAuthToken(secretId);
    const onUseRead = engine.getOAuthAccessToken(secretId);
    release();
    const [, token] = await Promise.all([explicitRefresh, onUseRead]);

    expect(hits).toBe(1);
    expect(token).toBe("coalesced-access-token");
  });

  it("starts a fresh refresh once a prior one has settled", async () => {
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);

    let hits = 0;
    const defaultHandler = tokenEndpointHandler;
    tokenEndpointHandler = (req, res) => {
      hits++;
      defaultHandler(req, res);
    };

    await engine.refreshOAuthToken(secretId);
    await engine.refreshOAuthToken(secretId);

    expect(hits).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// refreshOAuthToken — token-endpoint auth methods (migration 011)
// ---------------------------------------------------------------------------

describe("refreshOAuthToken token-endpoint auth methods", () => {
  interface CapturedTokenRequest {
    authorization: string | undefined;
    body: URLSearchParams;
  }

  let captured: CapturedTokenRequest[];

  /** Record every token-endpoint request (auth header + parsed form body), respond 200. */
  function captureTokenRequests(): void {
    captured = [];
    tokenEndpointHandler = (req, res) => {
      let data = "";
      req.on("data", (chunk: Buffer) => {
        data += chunk.toString("utf8");
      });
      req.on("end", () => {
        captured.push({
          authorization: req.headers.authorization,
          body: new URLSearchParams(data),
        });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "refreshed-access-token",
            refresh_token: "refreshed-refresh-token",
            expires_in: 3600,
          }),
        );
      });
    };
  }

  async function createActiveOAuthSecret(
    name: string,
    overrides?: Partial<OAuthProviderConfig>,
  ): Promise<string> {
    const { secretId } = await engine.createOAuthSecret(name, defaultProviderConfig(overrides));
    await engine.completeOAuthFlow(secretId, "old-access", "old-refresh", Date.now() - 1000);
    return secretId;
  }

  beforeEach(async () => {
    await engine.initVault("password");
    captureTokenRequests();
  });

  it("client_secret_basic sends Authorization: Basic and keeps credentials out of the body", async () => {
    const secretId = await createActiveOAuthSecret("basic-refresh", {
      token_endpoint_auth_method: "client_secret_basic",
    });

    await engine.refreshOAuthToken(secretId);

    expect(captured).toHaveLength(1);
    const request = captured[0] as CapturedTokenRequest;
    // Expected header computed inline with the RFC 6749 §2.3.1 recipe — not
    // via the shared helper, which is the implementation under test.
    const expected = `Basic ${Buffer.from(
      `${encodeURIComponent("my-client-id")}:${encodeURIComponent("my-client-secret")}`,
      "utf8",
    ).toString("base64")}`;
    expect(request.authorization).toBe(expected);
    expect(request.body.get("grant_type")).toBe("refresh_token");
    expect(request.body.get("refresh_token")).toBe("old-refresh");
    expect(request.body.has("client_id")).toBe(false);
    expect(request.body.has("client_secret")).toBe(false);

    expect(await engine.getOAuthAccessToken(secretId)).toBe("refreshed-access-token");
  });

  it("form-urlencodes credential halves through the full encrypt-store-refresh stack", async () => {
    const clientId = "cid:with/reserved%chars+";
    const clientSecret = "se:cret%20+/?";
    const secretId = await createActiveOAuthSecret("encoding-refresh", {
      client_id: clientId,
      client_secret: clientSecret,
      token_endpoint_auth_method: "client_secret_basic",
    });

    await engine.refreshOAuthToken(secretId);

    const authorization = (captured[0] as CapturedTokenRequest).authorization as string;
    const pair = Buffer.from(authorization.replace(/^Basic /, ""), "base64").toString("utf8");
    const separator = pair.indexOf(":");
    expect(decodeURIComponent(pair.slice(0, separator))).toBe(clientId);
    expect(decodeURIComponent(pair.slice(separator + 1))).toBe(clientSecret);
  });

  it("no stored method refreshes with credentials in the body (legacy wire shape)", async () => {
    const secretId = await createActiveOAuthSecret("legacy-refresh");

    await engine.refreshOAuthToken(secretId);

    const request = captured[0] as CapturedTokenRequest;
    expect(request.authorization).toBeUndefined();
    expect(request.body.get("client_id")).toBe("my-client-id");
    expect(request.body.get("client_secret")).toBe("my-client-secret");
    expect(request.body.get("refresh_token")).toBe("old-refresh");
  });

  it("explicit client_secret_post refreshes with credentials in the body", async () => {
    const secretId = await createActiveOAuthSecret("post-refresh", {
      token_endpoint_auth_method: "client_secret_post",
    });

    await engine.refreshOAuthToken(secretId);

    const request = captured[0] as CapturedTokenRequest;
    expect(request.authorization).toBeUndefined();
    expect(request.body.get("client_id")).toBe("my-client-id");
    expect(request.body.get("client_secret")).toBe("my-client-secret");
  });

  it("a NULL column and an unknown stored value both degrade to client_secret_post", async () => {
    const secretId = await createActiveOAuthSecret("degrade-refresh", {
      token_endpoint_auth_method: "client_secret_basic",
    });

    const db = new Database(dbPath);
    db.prepare("UPDATE oauth_tokens SET token_endpoint_auth_method = NULL WHERE secret_id = ?").run(
      secretId,
    );
    db.close();
    await engine.refreshOAuthToken(secretId);

    let request = captured[0] as CapturedTokenRequest;
    expect(request.authorization).toBeUndefined();
    expect(request.body.get("client_id")).toBe("my-client-id");

    const db2 = new Database(dbPath);
    db2
      .prepare("UPDATE oauth_tokens SET token_endpoint_auth_method = ? WHERE secret_id = ?")
      .run("private_key_jwt", secretId);
    db2.close();
    await engine.refreshOAuthToken(secretId);

    request = captured[1] as CapturedTokenRequest;
    expect(request.authorization).toBeUndefined();
    expect(request.body.get("client_id")).toBe("my-client-id");
    expect(request.body.get("client_secret")).toBe("my-client-secret");
  });

  it("client_secret_basic without a stored secret falls back to client_id in the body", async () => {
    const secretId = await createActiveOAuthSecret("public-refresh", {
      client_secret: undefined,
      token_endpoint_auth_method: "client_secret_basic",
    });

    await engine.refreshOAuthToken(secretId);

    const request = captured[0] as CapturedTokenRequest;
    expect(request.authorization).toBeUndefined();
    expect(request.body.get("client_id")).toBe("my-client-id");
    expect(request.body.has("client_secret")).toBe(false);
  });

  it("createOAuthSecret persists the method to the row, defaulting to NULL", async () => {
    const { secretId: basicId } = await engine.createOAuthSecret(
      "persist-basic",
      defaultProviderConfig({ token_endpoint_auth_method: "client_secret_basic" }),
    );
    const { secretId: defaultId } = await engine.createOAuthSecret(
      "persist-default",
      defaultProviderConfig(),
    );

    const db = new Database(dbPath, { readonly: true });
    const rows = db
      .prepare("SELECT secret_id, token_endpoint_auth_method FROM oauth_tokens")
      .all() as { secret_id: string; token_endpoint_auth_method: string | null }[];
    db.close();

    expect(rows.find((r) => r.secret_id === basicId)?.token_endpoint_auth_method).toBe(
      "client_secret_basic",
    );
    expect(rows.find((r) => r.secret_id === defaultId)?.token_endpoint_auth_method).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// getOAuthTokenStatus
// ---------------------------------------------------------------------------

describe("getOAuthTokenStatus", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    const result = await engine.createOAuthSecret("status-test", defaultProviderConfig());
    secretId = result.secretId;
  });

  it("returns expiring_soon when token expires within 5 minutes", async () => {
    const expiresAt = Date.now() + 2 * 60 * 1000; // 2 minutes
    await engine.completeOAuthFlow(secretId, "tok", "refresh", expiresAt);

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.refresh_status).toBe("expiring_soon");
  });

  it("surfaces the configured token-endpoint auth method, null for legacy rows", async () => {
    expect(engine.getOAuthTokenStatus(secretId).token_endpoint_auth_method).toBeNull();

    const basic = await engine.createOAuthSecret(
      "status-basic",
      defaultProviderConfig({ token_endpoint_auth_method: "client_secret_basic" }),
    );
    expect(engine.getOAuthTokenStatus(basic.secretId).token_endpoint_auth_method).toBe(
      "client_secret_basic",
    );

    const post = await engine.createOAuthSecret(
      "status-post",
      defaultProviderConfig({ token_endpoint_auth_method: "client_secret_post" }),
    );
    expect(engine.getOAuthTokenStatus(post.secretId).token_endpoint_auth_method).toBe(
      "client_secret_post",
    );
  });

  it("returns expired when token has expired", async () => {
    await engine.completeOAuthFlow(secretId, "tok", "refresh", Date.now() - 1000);

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.refresh_status).toBe("expired");
  });

  it("returns ok when token is valid and not expiring soon", async () => {
    const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hour
    await engine.completeOAuthFlow(secretId, "tok", "refresh", expiresAt);

    const status = engine.getOAuthTokenStatus(secretId);
    expect(status.refresh_status).toBe("ok");
  });
});

// ---------------------------------------------------------------------------
// getOAuthAccessToken
// ---------------------------------------------------------------------------

describe("getOAuthAccessToken", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    const result = await engine.createOAuthSecret("access-test", defaultProviderConfig());
    secretId = result.secretId;
  });

  it("returns decrypted access token", async () => {
    await engine.completeOAuthFlow(secretId, "my-secret-token", "refresh", Date.now() + 3600_000);

    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("my-secret-token");
  });

  it("auto-refreshes when token is expired", async () => {
    await engine.completeOAuthFlow(secretId, "expired-token", "refresh-tok", Date.now() - 5000);

    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("refreshed-access-token");
  });

  it("auto-refreshes when token is within 60s of expiry", async () => {
    await engine.completeOAuthFlow(
      secretId,
      "almost-expired",
      "refresh-tok",
      Date.now() + 30_000, // 30s — within 60s buffer
    );

    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("refreshed-access-token");
  });

  it("throws when token is expired and no refresh token", async () => {
    await engine.completeOAuthFlow(secretId, "expired-tok", undefined, Date.now() - 5000);

    await expect(engine.getOAuthAccessToken(secretId)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_REFRESH_FAILED,
    });
  });

  it("throws when OAuth flow not completed (PENDING)", async () => {
    // Secret is still PENDING — no completeOAuthFlow called
    await expect(engine.getOAuthAccessToken(secretId)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_NOT_CONFIGURED,
    });
  });

  it("logs a denied access-token read with success=false", async () => {
    await expect(engine.getOAuthAccessToken(secretId)).rejects.toThrow();

    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .filter((e) => !e.success);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.detail?.error).toBe(ErrorCode.OAUTH_NOT_CONFIGURED);
    expect(denied[0]?.secret_id).toBe(secretId);
  });

  it("throws for non-OAuth secrets", async () => {
    await engine.createSecret({
      name: "regular-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });
    const apiKeyId = await engine.resolveSecretId("secret://regular-key");

    await expect(engine.getOAuthAccessToken(apiKeyId)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_NOT_CONFIGURED,
    });
  });
});

// ---------------------------------------------------------------------------
// useSecret with OAuth auto-refresh
// ---------------------------------------------------------------------------

describe("useSecret with OAuth", () => {
  let secretId: string;

  beforeEach(async () => {
    await engine.initVault("password");
    const result = await engine.createOAuthSecret("use-test", defaultProviderConfig());
    secretId = result.secretId;
  });

  it("uses OAuth access token for HTTP injection (bearer)", async () => {
    await engine.completeOAuthFlow(secretId, "bearer-token-value", "refresh", Date.now() + 3600_000);

    const response = await engine.useSecret("secret://use-test", {
      type: "http",
      method: "GET",
      url: `${targetServerUrl}/api/data`,
      injection: { type: "bearer" },
    });

    if (response.type !== "http") throw new Error("expected http result");
    expect(response.status).toBe(200);
    // Token is correctly redacted from response (server echoes Authorization header)
    const body = JSON.parse(response.body ?? "{}");
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });

  it("auto-refreshes expired OAuth token before HTTP injection", async () => {
    await engine.completeOAuthFlow(secretId, "old-token", "refresh-tok", Date.now() - 5000);

    const response = await engine.useSecret("secret://use-test", {
      type: "http",
      method: "GET",
      url: `${targetServerUrl}/api/data`,
      injection: { type: "bearer" },
    });

    if (response.type !== "http") throw new Error("expected http result");
    expect(response.status).toBe(200);
    // Refreshed token is used and redacted from response
    const body = JSON.parse(response.body ?? "{}");
    expect(body.authorization).toBe("Bearer [REDACTED]");

    // Verify the refresh actually happened by checking the stored token
    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("refreshed-access-token");
  });
});
