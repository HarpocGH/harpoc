import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { CallerContext } from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";
import { OAuthManager } from "./oauth-manager.js";
import {
  authCodeConfig,
  clientCredentialsConfig,
  defaultTokenHandler,
  deviceCodeConfig,
  fakeEngineManager,
  makeFakeEngine,
  useLoopbackEndpoints,
} from "./__fixtures__/oauth-manager-fixtures.js";
import type { Handler } from "./__fixtures__/oauth-manager-fixtures.js";
import { expectVaultError } from "@harpoc/test-utils";

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
let tokenHandler: Handler;
let deviceHandler: Handler;
const endpoints = useLoopbackEndpoints(
  () => tokenHandler,
  () => deviceHandler,
);
const makeClientCredentialsConfig = () => clientCredentialsConfig(endpoints.tokenUrl());
const makeAuthCodeConfig = () => authCodeConfig(endpoints.tokenUrl());
const makeDeviceCodeConfig = () => deviceCodeConfig(endpoints.tokenUrl(), endpoints.deviceUrl());

beforeEach(() => {
  tokenHandler = defaultTokenHandler;
});

function useRealEngine(): void {
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
  });

  afterEach(async () => {
    await engine.destroy();
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
}

describe("B26: client_secret_basic with no client secret is refused at flow start", () => {
  useRealEngine();

  const MESSAGE =
    "client_secret_basic requires a client secret: the method sends the client credentials in an Authorization header, which a public client cannot form — supply the secret, or choose client_secret_post (the default) for a public client";

  async function expectRefusedWithoutRow(name: string, start: () => Promise<unknown>) {
    const err = await expectVaultError(start, ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(MESSAGE);
    await expectVaultError(
      () => engine.resolveSecretId(`secret://${name}`),
      ErrorCode.SECRET_NOT_FOUND,
    );
  }

  it("client_credentials", async () => {
    const manager = new OAuthManager(engine);
    const config = {
      ...makeClientCredentialsConfig(),
      token_endpoint_auth_method: "client_secret_basic" as const,
    };
    delete (config as { client_secret?: string }).client_secret;
    await expectRefusedWithoutRow("cc-basic", () =>
      manager.startClientCredentials("cc-basic", config),
    );
  });

  it("client_credentials with an empty secret", async () => {
    const manager = new OAuthManager(engine);
    const config = {
      ...makeClientCredentialsConfig(),
      client_secret: "",
      token_endpoint_auth_method: "client_secret_basic" as const,
    };
    await expectRefusedWithoutRow("cc-empty", () =>
      manager.startClientCredentials("cc-empty", config),
    );
  });

  it("authorization_code (deferred)", async () => {
    const manager = new OAuthManager(engine);
    const config = {
      ...makeAuthCodeConfig(),
      token_endpoint_auth_method: "client_secret_basic" as const,
    };
    delete (config as { client_secret?: string }).client_secret;
    await expectRefusedWithoutRow("ac-basic", () =>
      manager.startAuthorizationCodeDeferred("ac-basic", config),
    );
  });

  it("device_code", async () => {
    const manager = new OAuthManager(engine);
    const config = {
      ...makeDeviceCodeConfig(),
      token_endpoint_auth_method: "client_secret_basic" as const,
    };
    await expectRefusedWithoutRow("dc-basic", () => manager.startDeviceCode("dc-basic", config));
  });

  it("client_secret_basic with a secret, and client_secret_post without one, still start", async () => {
    const manager = new OAuthManager(engine);
    const withSecret = {
      ...makeClientCredentialsConfig(),
      token_endpoint_auth_method: "client_secret_basic" as const,
    };
    await expect(manager.startClientCredentials("cc-ok", withSecret)).resolves.toMatchObject({
      status: "authorized",
    });
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "DEV-CODE-PUBLIC",
          user_code: "PUBLIC-1234",
          verification_uri: "https://example.com/device",
          expires_in: 900,
          interval: 5,
        }),
      );
    };
    const publicDevice = makeDeviceCodeConfig();
    const started = await manager.startDeviceCode("dc-public", publicDevice);
    expect(started.handle).toBe("secret://dc-public");
    manager.cancelPendingFlows();
  });
});

describe("OAuthManager.startClientCredentials", () => {
  useRealEngine();

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
    expect((await engine.getSecretInfo("secret://fail-cc")).status).toBe("pending");
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
  useRealEngine();

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
          await fetch(`${redirectUri}?code=bad-code&state=${state}`);
        }
      },
    });

    await expect(
      manager.startAuthorizationCode("fail-auth", makeAuthCodeConfig()),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED });
    expect((await engine.getSecretInfo("secret://fail-auth")).status).toBe("pending");
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
    expect((await engine.getSecretInfo("secret://timeout-auth")).status).toBe("pending");
  });
});

describe("OAuthManager.startDeviceCode", () => {
  useRealEngine();

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
  useRealEngine();

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

// ---------------------------------------------------------------------------
// Deferred authorization-code start (D9) + caller threading
// ---------------------------------------------------------------------------

describe("OAuthManager.startAuthorizationCodeDeferred", () => {
  it("resolves before any callback, with the auth URL bound to the live callback port", async () => {
    const fake = makeFakeEngine();
    const openBrowser = vi.fn(async () => undefined);
    const manager = fakeEngineManager(fake, { callbackPort: 0, openBrowser });

    const start = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());

    expect(start.handle).toBe("secret://gh");
    expect(start.secretId).toBe("sid-1");
    expect(openBrowser).not.toHaveBeenCalled();
    expect(fake.completeOAuthFlow).not.toHaveBeenCalled();

    const authUrl = new URL(start.authUrl);
    expect(authUrl.origin + authUrl.pathname).toBe("https://example.com/auth");
    expect(authUrl.searchParams.get("state")).toMatch(/^[0-9a-f]{64}$/);
    expect(authUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");

    const redirectUri = new URL(authUrl.searchParams.get("redirect_uri") as string);
    expect(redirectUri.pathname).toBe("/oauth/callback");
    expect(Number(redirectUri.port)).toBeGreaterThan(0);
    // Proof the port is the actually bound one, not the requested 0: the
    // callback server answers on it (404 for a non-callback path leaves the
    // flow undisturbed).
    const probe = await fetch(`http://127.0.0.1:${redirectUri.port}/not-the-callback`);
    expect(probe.status).toBe(404);

    expect(manager.cancelFlow(start.secretId)).toBe(true);
    await expect(start.completion).rejects.toBeDefined();
  });

  it("completes on callback: completion resolves and the token reaches completeOAuthFlow", async () => {
    const fake = makeFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0 });

    const start = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
    const authUrl = new URL(start.authUrl);
    const state = authUrl.searchParams.get("state") as string;
    const redirectUri = authUrl.searchParams.get("redirect_uri") as string;

    const res = await fetch(`${redirectUri}?code=deferred-code&state=${state}`);
    expect(res.status).toBe(200);

    await expect(start.completion).resolves.toBeUndefined();
    expect(fake.completeOAuthFlow).toHaveBeenCalledWith(
      "sid-1",
      "mgr-access-token",
      "mgr-refresh-token",
      expect.any(Number),
    );
  });

  it("cancelFlow rejects completion and stays silent on onBackgroundFlowError", async () => {
    const fake = makeFakeEngine();
    const errors: unknown[] = [];
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });

    const start = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
    const redirectUri = new URL(new URL(start.authUrl).searchParams.get("redirect_uri") as string);

    expect(manager.cancelFlow(start.secretId)).toBe(true);
    await expect(start.completion).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
      message: "OAuth flow failed: Authorization flow aborted",
    });
    expect(errors).toHaveLength(0);
    expect(fake.completeOAuthFlow).not.toHaveBeenCalled();

    // The abort stopped the callback server: nothing answers on the port
    // (a still-live server would answer the non-callback path with 404).
    await vi.waitFor(async () => {
      await expect(
        fetch(`http://127.0.0.1:${redirectUri.port}/not-the-callback`),
      ).rejects.toThrow();
    });
    await vi.waitFor(() => {
      expect(manager.cancelFlow(start.secretId)).toBe(false);
    });
  });

  it("cancelPendingFlows cancels an authorization-code flow like cancelFlow does", async () => {
    const fake = makeFakeEngine();
    const errors: unknown[] = [];
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });

    const start = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
    const redirectUri = new URL(new URL(start.authUrl).searchParams.get("redirect_uri") as string);

    manager.cancelPendingFlows();
    await expect(start.completion).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
      message: "OAuth flow failed: Authorization flow aborted",
    });
    expect(errors).toHaveLength(0);
    expect(fake.completeOAuthFlow).not.toHaveBeenCalled();

    // The abort stopped the callback server: nothing answers on the port
    // (a still-live server would answer the non-callback path with 404).
    await vi.waitFor(async () => {
      await expect(
        fetch(`http://127.0.0.1:${redirectUri.port}/not-the-callback`),
      ).rejects.toThrow();
    });

    // Deregistered, so a second sweep has nothing left to abort.
    await vi.waitFor(() => {
      expect(manager.cancelFlow(start.secretId)).toBe(false);
    });
    manager.cancelPendingFlows();
    expect(manager.cancelFlow(start.secretId)).toBe(false);
    expect(errors).toHaveLength(0);
  });

  it("an unfetched callback times out: completion rejects and onBackgroundFlowError fires", async () => {
    const fake = makeFakeEngine();
    const errors: { secretId: string; err: unknown }[] = [];
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      callbackTimeoutMs: 100,
      onBackgroundFlowError: (secretId, err) => {
        errors.push({ secretId, err });
      },
    });

    const start = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());

    await expect(start.completion).rejects.toMatchObject({
      code: ErrorCode.OAUTH_CALLBACK_TIMEOUT,
    });
    await vi.waitFor(() => {
      expect(errors).toHaveLength(1);
    });
    expect(errors[0]?.secretId).toBe("sid-1");
    expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
  });

  it("a throwing onBackgroundFlowError does not become an unhandled rejection", async () => {
    const fake = makeFakeEngine();
    const unhandled = vi.fn();
    let onBackgroundFlowErrorCalls = 0;
    process.once("unhandledRejection", unhandled);
    try {
      const manager = fakeEngineManager(fake, {
        callbackPort: 0,
        callbackTimeoutMs: 100,
        onBackgroundFlowError: () => {
          onBackgroundFlowErrorCalls++;
          throw new Error("embedder bug");
        },
      });

      const start = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
      await expect(start.completion).rejects.toMatchObject({
        code: ErrorCode.OAUTH_CALLBACK_TIMEOUT,
      });

      await vi.waitFor(() => {
        expect(manager.cancelFlow(start.secretId)).toBe(false);
      });
      // Node emits unhandledRejection a turn after the microtask queue drains.
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(onBackgroundFlowErrorCalls).toBe(1);
      expect(unhandled).not.toHaveBeenCalled();
    } finally {
      process.off("unhandledRejection", unhandled);
    }
  });
});

describe("OAuthManager caller threading (D9)", () => {
  const caller: CallerContext = {
    principal_type: "agent",
    principal_id: "agent-7",
    project: "api",
    interface: "rest",
  };

  it("startDeviceCode forwards the caller as createOAuthSecret's 4th argument", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "dc-caller",
          user_code: "USER-CALLER",
          verification_uri: "https://example.com/device",
          interval: 0,
          expires_in: 60,
        }),
      );
    };

    const fake = makeFakeEngine();
    const manager = fakeEngineManager(fake);

    const result = await manager.startDeviceCode("gh", makeDeviceCodeConfig(), undefined, caller);
    await result.completion;

    expect(fake.createOAuthSecret).toHaveBeenCalledWith(
      "gh",
      expect.objectContaining({ client_id: "device-client" }),
      undefined,
      caller,
    );
  });

  it("startClientCredentials forwards the caller as createOAuthSecret's 4th argument", async () => {
    const fake = makeFakeEngine();
    const manager = fakeEngineManager(fake);

    await manager.startClientCredentials("gh", makeClientCredentialsConfig(), "my-project", caller);

    expect(fake.createOAuthSecret).toHaveBeenCalledWith(
      "gh",
      expect.objectContaining({ client_id: "cc-client" }),
      "my-project",
      caller,
    );
  });

  it("startAuthorizationCodeDeferred forwards the caller as createOAuthSecret's 4th argument", async () => {
    const fake = makeFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0 });

    const start = await manager.startAuthorizationCodeDeferred(
      "gh",
      makeAuthCodeConfig(),
      "my-project",
      caller,
    );

    expect(fake.createOAuthSecret).toHaveBeenCalledWith(
      "gh",
      expect.objectContaining({ client_id: "auth-code-client" }),
      "my-project",
      caller,
    );

    manager.cancelFlow(start.secretId);
    await expect(start.completion).rejects.toBeDefined();
  });
});

describe("OAuthManager.startAuthorizationCode (blocking wrapper over the deferred start)", () => {
  it("cancels the flow and rethrows a wrapped error when the browser cannot open", async () => {
    const fake = makeFakeEngine();
    const errors: unknown[] = [];
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      openBrowser: async () => {
        throw new Error("no display");
      },
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });

    await expect(manager.startAuthorizationCode("gh", makeAuthCodeConfig())).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });

    expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
    expect(errors).toHaveLength(0);
    await vi.waitFor(() => {
      expect(manager.cancelFlow("sid-1")).toBe(false);
    });
  });
});
