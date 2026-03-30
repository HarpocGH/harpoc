import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

    const response = await engine.useSecret(
      "secret://use-test",
      { method: "GET", url: `${targetServerUrl}/api/data` },
      { type: "bearer" },
    );

    expect(response.status).toBe(200);
    // Token is correctly redacted from response (server echoes Authorization header)
    const body = JSON.parse(response.body ?? "{}");
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });

  it("auto-refreshes expired OAuth token before HTTP injection", async () => {
    await engine.completeOAuthFlow(secretId, "old-token", "refresh-tok", Date.now() - 5000);

    const response = await engine.useSecret(
      "secret://use-test",
      { method: "GET", url: `${targetServerUrl}/api/data` },
      { type: "bearer" },
    );

    expect(response.status).toBe(200);
    // Refreshed token is used and redacted from response
    const body = JSON.parse(response.body ?? "{}");
    expect(body.authorization).toBe("Bearer [REDACTED]");

    // Verify the refresh actually happened by checking the stored token
    const token = await engine.getOAuthAccessToken(secretId);
    expect(token).toBe("refreshed-access-token");
  });
});
