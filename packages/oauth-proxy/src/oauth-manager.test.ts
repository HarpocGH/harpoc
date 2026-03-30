import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";
import { OAuthManager } from "./oauth-manager.js";

// Mock argon2 for speed (same approach as core tests)
vi.mock("argon2", () => ({
  hash: async (password: Buffer | string, opts: { salt: Buffer | Uint8Array }) => {
    const { createHash } = await import("node:crypto");
    const salt = opts.salt instanceof Uint8Array ? Buffer.from(opts.salt) : opts.salt;
    return createHash("sha256")
      .update(typeof password === "string" ? password : Buffer.from(password))
      .update(salt)
      .digest();
  },
}));

let tempDir: string;
let engine: VaultEngine;
let tokenServer: Server;
let tokenServerUrl: string;
let tokenHandler: (req: IncomingMessage, res: ServerResponse) => void;
let deviceServer: Server;
let deviceServerUrl: string;
let deviceHandler: (req: IncomingMessage, res: ServerResponse) => void;

beforeAll(async () => {
  tokenServer = createServer((req, res) => {
    tokenHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    tokenServer.listen(0, "127.0.0.1", () => resolve());
  });
  const tokenAddr = tokenServer.address() as { port: number };
  tokenServerUrl = `http://127.0.0.1:${tokenAddr.port}`;

  deviceServer = createServer((req, res) => {
    deviceHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    deviceServer.listen(0, "127.0.0.1", () => resolve());
  });
  const deviceAddr = deviceServer.address() as { port: number };
  deviceServerUrl = `http://127.0.0.1:${deviceAddr.port}`;
});

afterAll(() => {
  tokenServer.close();
  deviceServer.close();
});

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-oauth-mgr-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");

  // Default token handler
  tokenHandler = (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        access_token: "mgr-access-token",
        refresh_token: "mgr-refresh-token",
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
    // ignore
  }
});

function makeClientCredentialsConfig(): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "client_credentials",
    token_endpoint: tokenServerUrl,
    client_id: "cc-client",
    client_secret: "cc-secret",
    scopes: ["api.read"],
  };
}

function makeAuthCodeConfig(): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "authorization_code",
    token_endpoint: tokenServerUrl,
    auth_endpoint: "https://example.com/auth",
    client_id: "auth-code-client",
    client_secret: "auth-code-secret",
  };
}

function makeDeviceCodeConfig(): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "device_code",
    token_endpoint: tokenServerUrl,
    device_authorization_endpoint: deviceServerUrl,
    client_id: "device-client",
  };
}

describe("OAuthManager.startClientCredentials", () => {
  it("completes client_credentials flow end-to-end", async () => {
    const manager = new OAuthManager(engine);
    const result = await manager.startClientCredentials("cc-secret", makeClientCredentialsConfig());

    expect(result.handle).toBe("secret://cc-secret");
    expect(result.status).toBe("authorized");

    const info = await engine.getSecretInfo("secret://cc-secret");
    expect(info.status).toBe("active");
    expect(info.type).toBe("oauth_token");
  });

  it("fails when token endpoint returns error", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_client" }));
    };

    const manager = new OAuthManager(engine);

    await expect(
      manager.startClientCredentials("fail-cc", makeClientCredentialsConfig()),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED });
  });

  it("creates secret in project", async () => {
    const manager = new OAuthManager(engine);
    const result = await manager.startClientCredentials(
      "proj-cc",
      makeClientCredentialsConfig(),
      "my-project",
    );

    expect(result.handle).toBe("secret://my-project/proj-cc");
  });
});

describe("OAuthManager.startAuthorizationCode", () => {
  it("creates secret and opens browser (mocked)", async () => {
    let openedUrl = "";
    const manager = new OAuthManager(engine, {
      callbackPort: 0,
      openBrowser: async (url) => {
        openedUrl = url;

        // Extract the redirect_uri from auth URL to know where to send callback
        const authUrl = new URL(url);
        const state = authUrl.searchParams.get("state");
        const redirectUri = authUrl.searchParams.get("redirect_uri");
        if (state && redirectUri) {
          // Give the callback server time to start listening
          await new Promise((r) => setTimeout(r, 50));
          await fetch(`${redirectUri}?code=auth-code-123&state=${state}`);
        }
      },
    });

    const result = await manager.startAuthorizationCode("auth-code-test", makeAuthCodeConfig());

    expect(result.handle).toBe("secret://auth-code-test");
    expect(result.status).toBe("authorized");
    expect(openedUrl).toContain("example.com/auth");
    expect(openedUrl).toContain("response_type=code");

    const info = await engine.getSecretInfo("secret://auth-code-test");
    expect(info.status).toBe("active");
  });

  it("propagates token exchange errors", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    };

    const manager = new OAuthManager(engine, {
      callbackPort: 0,
      openBrowser: async (url) => {
        const authUrl = new URL(url);
        const state = authUrl.searchParams.get("state");
        const redirectUri = authUrl.searchParams.get("redirect_uri");
        if (state && redirectUri) {
          await new Promise((r) => setTimeout(r, 50));
          await fetch(`${redirectUri}?code=bad-code&state=${state}`);
        }
      },
    });

    await expect(
      manager.startAuthorizationCode("fail-auth", makeAuthCodeConfig()),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED });
  });

  it("handles callback timeout", async () => {
    const manager = new OAuthManager(engine, {
      callbackPort: 0,
      callbackTimeoutMs: 100,
      openBrowser: async () => {
        // Don't send any callback — let it time out
      },
    });

    await expect(
      manager.startAuthorizationCode("timeout-auth", makeAuthCodeConfig()),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_CALLBACK_TIMEOUT });
  });
});

describe("OAuthManager.startDeviceCode", () => {
  it("returns pending_authorization with user code", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "DEV-CODE",
          user_code: "ABCD-1234",
          verification_uri: "https://example.com/device",
          expires_in: 900,
          interval: 5,
        }),
      );
    };

    const manager = new OAuthManager(engine);
    const result = await manager.startDeviceCode("device-test", makeDeviceCodeConfig());

    expect(result.handle).toBe("secret://device-test");
    expect(result.status).toBe("pending_authorization");
    expect(result.auth_url).toBe("https://example.com/device");
    expect(result.user_code).toBe("ABCD-1234");
    expect(result.message).toContain("ABCD-1234");
  });

  it("fails when device endpoint returns error", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(500);
      res.end("Server error");
    };

    const manager = new OAuthManager(engine);

    await expect(
      manager.startDeviceCode("fail-device", makeDeviceCodeConfig()),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
  });
});
