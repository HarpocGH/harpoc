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
  tempDir = join(tmpdir(), `harpoc-oauth-mgr-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

describe("OAuthManager device-code background poll lifecycle (code review Low O3)", () => {
  function pendingDeviceHandlers(): { tokenHits: () => number; release: () => void } {
    let hits = 0;
    let released = false;
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "dc-1",
          user_code: "USER-1",
          verification_uri: "https://example.com/device",
          interval: 0,
          expires_in: 60,
        }),
      );
    };
    tokenHandler = (_req, res) => {
      hits++;
      if (released) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "dev-access", expires_in: 3600 }));
      } else {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "authorization_pending" }));
      }
    };
    return {
      tokenHits: () => hits,
      release: () => {
        released = true;
      },
    };
  }

  it("cancelFlow aborts a pending background poll and the endpoint hit count freezes", async () => {
    const handlers = pendingDeviceHandlers();
    const manager = new OAuthManager(engine);

    const result = await manager.startDeviceCode("dev-cancel", makeDeviceCodeConfig());
    expect(result.status).toBe("pending_authorization");
    const secretId = await engine.resolveSecretId(result.handle);

    await vi.waitFor(() => {
      expect(handlers.tokenHits()).toBeGreaterThan(0);
    });
    expect(manager.cancelFlow(secretId)).toBe(true);

    // The poll promise settles and clears itself from the pending map...
    await vi.waitFor(() => {
      expect(manager.cancelFlow(secretId)).toBe(false);
    });
    // ...and no further polling reaches the endpoint. A request already on
    // the wire when the abort landed can arrive arbitrarily late on a loaded
    // runner, so wait for the endpoint to go quiet instead of a fixed drain:
    // the freeze is proven by a 200 ms window with no new hits — many
    // 0-interval poll iterations — which a live poll can never satisfy.
    await vi.waitFor(
      async () => {
        const before = handlers.tokenHits();
        await new Promise((r) => setTimeout(r, 200));
        expect(handlers.tokenHits()).toBe(before);
      },
      { timeout: 15_000, interval: 50 },
    );
  });

  it("surfaces a background completion failure via onBackgroundFlowError (sealed engine)", async () => {
    const handlers = pendingDeviceHandlers();
    const errors: { secretId: string; err: unknown }[] = [];
    const manager = new OAuthManager(engine, {
      onBackgroundFlowError: (secretId, err) => {
        errors.push({ secretId, err });
      },
    });

    const result = await manager.startDeviceCode("dev-fail", makeDeviceCodeConfig());
    const secretId = await engine.resolveSecretId(result.handle);

    await engine.lock(); // completeOAuthFlow will fail against a sealed engine
    handlers.release();

    await vi.waitFor(() => {
      expect(errors.length).toBeGreaterThanOrEqual(1);
    });
    expect(errors[0]?.secretId).toBe(secretId);
  });

  it("completion resolves after the user grant and the secret becomes ACTIVE", async () => {
    const handlers = pendingDeviceHandlers();
    const manager = new OAuthManager(engine);

    const result = await manager.startDeviceCode("dev-complete", makeDeviceCodeConfig());
    expect(result.status).toBe("pending_authorization");

    handlers.release();
    await result.completion;

    const info = await engine.getSecretInfo(result.handle);
    expect(info.status).toBe("active");
  });

  it("completion rejects when background completion fails (sealed engine)", async () => {
    const handlers = pendingDeviceHandlers();
    const manager = new OAuthManager(engine);

    const result = await manager.startDeviceCode("dev-reject", makeDeviceCodeConfig());

    await engine.lock();
    handlers.release();

    await expect(result.completion).rejects.toMatchObject({ code: ErrorCode.VAULT_LOCKED });
  });

  it("completion rejects after cancelFlow and onBackgroundFlowError stays silent", async () => {
    const handlers = pendingDeviceHandlers();
    const errors: unknown[] = [];
    const manager = new OAuthManager(engine, {
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });

    const result = await manager.startDeviceCode("dev-cancel-reject", makeDeviceCodeConfig());
    const secretId = await engine.resolveSecretId(result.handle);
    await vi.waitFor(() => {
      expect(handlers.tokenHits()).toBeGreaterThan(0);
    });

    expect(manager.cancelFlow(secretId)).toBe(true);
    await expect(result.completion).rejects.toBeDefined();
    expect(errors).toHaveLength(0);
  });

  it("an aborted poll is not reported as a background error", async () => {
    const handlers = pendingDeviceHandlers();
    const errors: unknown[] = [];
    const manager = new OAuthManager(engine, {
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });

    const result = await manager.startDeviceCode("dev-silent", makeDeviceCodeConfig());
    const secretId = await engine.resolveSecretId(result.handle);
    await vi.waitFor(() => {
      expect(handlers.tokenHits()).toBeGreaterThan(0);
    });

    manager.cancelPendingFlows();
    await vi.waitFor(() => {
      expect(manager.cancelFlow(secretId)).toBe(false);
    });
    expect(errors).toHaveLength(0);
  });
});
