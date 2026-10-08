import { createServer } from "node:http";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { CallbackServer } from "./callback-server.js";
import { DEFAULT_MAX_PENDING_AUTHORIZATIONS } from "./oauth-manager.js";
import {
  authCodeConfig,
  clientCredentialsConfig,
  defaultTokenHandler,
  deviceCodeConfig,
  fakeEngineManager,
  gateCallbackServerStart,
  makeFakeEngine,
  makePerNameFakeEngine,
  useLoopbackEndpoints,
} from "./__fixtures__/oauth-manager-fixtures.js";
import type { Handler } from "./__fixtures__/oauth-manager-fixtures.js";

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

/** `promise`, or a rejection naming the deadline — a hung completion fails the case, not the file. */
function within<T>(promise: Promise<T>, ms = 10_000): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`still pending after ${String(ms)} ms`)), ms).unref();
    }),
  ]);
}

function pendingDeviceCodeHandler(): void {
  deviceHandler = (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        device_code: "dc-cap",
        user_code: "USER-CAP",
        verification_uri: "https://example.com/device",
        // Long interval: the background poll sleeps for the whole test rather
        // than hammering the token endpoint.
        interval: 60,
        expires_in: 600,
      }),
    );
  };
}

describe("OAuthManager.startAuthorizationCodeDeferred", () => {
  it("a restart for the same secret supersedes the first flow and keeps the second cancellable", async () => {
    const fake = makeFakeEngine();
    const errors: unknown[] = [];
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });

    // Same name: createOAuthSecret resumes the PENDING secret and returns the
    // SAME secretId, so both starts land on one pendingFlows key.
    const first = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
    const firstPort = new URL(new URL(first.authUrl).searchParams.get("redirect_uri") as string)
      .port;
    const second = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
    const secondPort = new URL(new URL(second.authUrl).searchParams.get("redirect_uri") as string)
      .port;
    expect(second.secretId).toBe(first.secretId);
    expect(secondPort).not.toBe(firstPort);

    // The superseded flow is aborted, not reported as a background failure...
    await expect(first.completion).rejects.toBeDefined();
    expect(errors).toHaveLength(0);
    // ...and its callback server is gone, so its redirect can no longer be
    // exchanged behind the caller's back.
    await vi.waitFor(async () => {
      await expect(fetch(`http://127.0.0.1:${firstPort}/not-the-callback`)).rejects.toThrow();
    });

    // The survivor is still live and still cancellable (the superseded flow's
    // cleanup must not delete the successor's registration).
    const probe = await fetch(`http://127.0.0.1:${secondPort}/not-the-callback`);
    expect(probe.status).toBe(404);
    expect(manager.cancelFlow(second.secretId)).toBe(true);
    await expect(second.completion).rejects.toBeDefined();

    expect(errors).toHaveLength(0);
    expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
  });

  it("a predecessor whose token exchange is in flight when a restart re-inserts the row never stores its tokens", async () => {
    // A token endpoint the test holds: the first flow's exchange parks here
    // while the second start re-inserts the row and binds.
    let exchangeParked = false;
    let releaseExchange: () => void = () => undefined;
    const held = createServer((_req, res) => {
      releaseExchange = () => {
        releaseExchange = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "old-flow-token",
            token_type: "bearer",
            expires_in: 3600,
          }),
        );
      };
      exchangeParked = true;
    });
    await new Promise<void>((resolve) => held.listen(0, "127.0.0.1", () => resolve()));
    const heldUrl = `http://127.0.0.1:${(held.address() as { port: number }).port}`;
    try {
      const fake = makeFakeEngine();
      const errors: unknown[] = [];
      const manager = fakeEngineManager(fake, {
        callbackPort: 0,
        onBackgroundFlowError: (_secretId, err) => {
          errors.push(err);
        },
      });

      const first = await manager.startAuthorizationCodeDeferred("gh", {
        ...makeAuthCodeConfig(),
        token_endpoint: heldUrl,
      });
      const firstRedirect = new URL(
        new URL(first.authUrl).searchParams.get("redirect_uri") as string,
      );
      const state = new URL(first.authUrl).searchParams.get("state") as string;
      firstRedirect.searchParams.set("code", "old-code");
      firstRedirect.searchParams.set("state", state);
      await fetch(firstRedirect);
      await vi.waitFor(() => expect(exchangeParked).toBe(true));

      const second = await manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
      expect(second.secretId).toBe(first.secretId);
      releaseExchange();

      await expect(first.completion).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
      expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
      expect(errors).toHaveLength(0);
      expect(manager.cancelFlow(second.secretId)).toBe(true);
      await expect(second.completion).rejects.toBeDefined();
    } finally {
      releaseExchange();
      held.closeAllConnections();
      await new Promise<void>((resolve) => held.close(() => resolve()));
    }
  });

  it("two concurrent client-credentials starts for one name: the first never stores, the second does (P1bF-1)", async () => {
    let exchangeParked = false;
    let releaseExchange: () => void = () => undefined;
    const held = createServer((_req, res) => {
      releaseExchange = () => {
        releaseExchange = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "old-flow-token",
            token_type: "bearer",
            expires_in: 3600,
          }),
        );
      };
      exchangeParked = true;
    });
    await new Promise<void>((resolve) => held.listen(0, "127.0.0.1", () => resolve()));
    const heldUrl = `http://127.0.0.1:${(held.address() as { port: number }).port}`;
    try {
      const fake = makeFakeEngine();
      const manager = fakeEngineManager(fake, {});
      const first = manager.startClientCredentials("gh", {
        ...makeClientCredentialsConfig(),
        token_endpoint: heldUrl,
      });
      first.catch(() => undefined);
      await vi.waitFor(() => expect(exchangeParked).toBe(true));

      const second = await manager.startClientCredentials("gh", makeClientCredentialsConfig());
      expect(second.status).toBe("authorized");
      releaseExchange();

      await expect(first).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
      expect(fake.completeOAuthFlow).toHaveBeenCalledTimes(1);
      expect(fake.completeOAuthFlow.mock.calls[0]?.[1]).not.toBe("old-flow-token");
    } finally {
      releaseExchange();
      held.closeAllConnections();
      await new Promise<void>((resolve) => held.close(() => resolve()));
    }
  });

  it("a client-credentials restart over a parked authorization-code exchange supersedes it (P1bF-1)", async () => {
    let exchangeParked = false;
    let releaseExchange: () => void = () => undefined;
    const held = createServer((_req, res) => {
      releaseExchange = () => {
        releaseExchange = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "old-flow-token",
            token_type: "bearer",
            expires_in: 3600,
          }),
        );
      };
      exchangeParked = true;
    });
    await new Promise<void>((resolve) => held.listen(0, "127.0.0.1", () => resolve()));
    const heldUrl = `http://127.0.0.1:${(held.address() as { port: number }).port}`;
    try {
      const fake = makeFakeEngine();
      const errors: unknown[] = [];
      const manager = fakeEngineManager(fake, {
        callbackPort: 0,
        onBackgroundFlowError: (_secretId, err) => {
          errors.push(err);
        },
      });

      const first = await manager.startAuthorizationCodeDeferred("gh", {
        ...makeAuthCodeConfig(),
        token_endpoint: heldUrl,
      });
      const firstRedirect = new URL(
        new URL(first.authUrl).searchParams.get("redirect_uri") as string,
      );
      const state = new URL(first.authUrl).searchParams.get("state") as string;
      firstRedirect.searchParams.set("code", "old-code");
      firstRedirect.searchParams.set("state", state);
      await fetch(firstRedirect);
      await vi.waitFor(() => expect(exchangeParked).toBe(true));

      const second = await manager.startClientCredentials("gh", makeClientCredentialsConfig());
      expect(second.status).toBe("authorized");
      releaseExchange();

      await expect(first.completion).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
      expect(fake.completeOAuthFlow).toHaveBeenCalledTimes(1);
      expect(errors).toHaveLength(0);
    } finally {
      releaseExchange();
      held.closeAllConnections();
      await new Promise<void>((resolve) => held.close(() => resolve()));
    }
  });

  it("cancelFlow reaches a parked client-credentials exchange, which then never stores (P1bF-1)", async () => {
    let exchangeParked = false;
    let releaseExchange: () => void = () => undefined;
    const held = createServer((_req, res) => {
      releaseExchange = () => {
        releaseExchange = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "old-flow-token",
            token_type: "bearer",
            expires_in: 3600,
          }),
        );
      };
      exchangeParked = true;
    });
    await new Promise<void>((resolve) => held.listen(0, "127.0.0.1", () => resolve()));
    const heldUrl = `http://127.0.0.1:${(held.address() as { port: number }).port}`;
    try {
      const fake = makeFakeEngine();
      const manager = fakeEngineManager(fake, {});
      const first = manager.startClientCredentials("gh", {
        ...makeClientCredentialsConfig(),
        token_endpoint: heldUrl,
      });
      first.catch(() => undefined);
      await vi.waitFor(() => expect(exchangeParked).toBe(true));
      expect(manager.cancelFlow("sid-1")).toBe(true);
      releaseExchange();
      await expect(first).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
      expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
    } finally {
      releaseExchange();
      held.closeAllConnections();
      await new Promise<void>((resolve) => held.close(() => resolve()));
    }
  });

  it("a device-code restart supersedes a parked client-credentials exchange before it aborts it — the exchange never stores (P1bF-1)", async () => {
    let exchangeParked = false;
    let releaseExchange: () => void = () => undefined;
    const held = createServer((_req, res) => {
      releaseExchange = () => {
        releaseExchange = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "old-flow-token",
            token_type: "bearer",
            expires_in: 3600,
          }),
        );
      };
      exchangeParked = true;
    });
    await new Promise<void>((resolve) => held.listen(0, "127.0.0.1", () => resolve()));
    const heldUrl = `http://127.0.0.1:${(held.address() as { port: number }).port}`;
    let deviceParked = false;
    let releaseDevice: () => void = () => undefined;
    deviceHandler = (_req, res) => {
      releaseDevice = () => {
        releaseDevice = () => undefined;
        res.writeHead(500);
        res.end("Server error");
      };
      deviceParked = true;
    };
    try {
      const fake = makeFakeEngine();
      const manager = fakeEngineManager(fake, {});
      const first = manager.startClientCredentials("gh", {
        ...makeClientCredentialsConfig(),
        token_endpoint: heldUrl,
      });
      first.catch(() => undefined);
      await vi.waitFor(() => expect(exchangeParked).toBe(true));

      const second = manager.startDeviceCode("gh", makeDeviceCodeConfig());
      second.catch(() => undefined);
      await vi.waitFor(() => expect(deviceParked).toBe(true));
      releaseExchange();

      await expect(first).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
        message: "OAuth flow failed: OAuth flow superseded",
      });
      expect(fake.completeOAuthFlow).not.toHaveBeenCalled();

      releaseDevice();
      await expect(second).rejects.toBeDefined();
    } finally {
      releaseExchange();
      releaseDevice();
      held.closeAllConnections();
      await new Promise<void>((resolve) => held.close(() => resolve()));
    }
  });

  it("a predecessor whose exchange lands while the restart is still binding settles as superseded, silently", async () => {
    let exchangeParked = false;
    let releaseExchange: () => void = () => undefined;
    const held = createServer((_req, res) => {
      releaseExchange = () => {
        releaseExchange = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "old-flow-token", expires_in: 3600 }));
      };
      exchangeParked = true;
    });
    await new Promise<void>((resolve) => held.listen(0, "127.0.0.1", () => resolve()));
    const heldUrl = `http://127.0.0.1:${(held.address() as { port: number }).port}`;
    const fake = makeFakeEngine();
    const errors: unknown[] = [];
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });
    let startSpy: MockInstance<CallbackServer["start"]> | undefined;
    let releaseBind: () => void = () => undefined;
    try {
      const first = await manager.startAuthorizationCodeDeferred("gh", {
        ...makeAuthCodeConfig(),
        token_endpoint: heldUrl,
      });
      ({ startSpy, releaseBind } = gateCallbackServerStart());
      const firstRedirect = new URL(
        new URL(first.authUrl).searchParams.get("redirect_uri") as string,
      );
      firstRedirect.searchParams.set("code", "old-code");
      firstRedirect.searchParams.set(
        "state",
        new URL(first.authUrl).searchParams.get("state") as string,
      );
      await fetch(firstRedirect);
      await vi.waitFor(() => expect(exchangeParked).toBe(true));

      // The re-insert has happened, the successor's bind has not: the
      // predecessor is superseded but not yet aborted.
      const second = manager.startAuthorizationCodeDeferred("gh", makeAuthCodeConfig());
      await vi.waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));
      releaseExchange();

      await expect(first.completion).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
        message: "OAuth flow failed: OAuth flow superseded",
      });
      expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
      expect(errors).toHaveLength(0);

      releaseBind();
      const started = await second;
      expect(manager.cancelFlow(started.secretId)).toBe(true);
      await expect(started.completion).rejects.toBeDefined();
    } finally {
      startSpy?.mockRestore();
      releaseBind();
      releaseExchange();
      held.closeAllConnections();
      await new Promise<void>((resolve) => held.close(() => resolve()));
    }
  });

  it("a device-code predecessor whose token poll is in flight when a restart re-inserts the row never stores its tokens", async () => {
    let deviceStarts = 0;
    deviceHandler = (_req, res) => {
      deviceStarts += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: `dc-${deviceStarts}`,
          user_code: "USER-1",
          verification_uri: "https://example.com/device",
          // The first flow polls at once and parks; the second sleeps.
          interval: deviceStarts === 1 ? 0 : 60,
          expires_in: 600,
        }),
      );
    };
    let pollParked = false;
    let releasePoll: () => void = () => undefined;
    tokenHandler = (_req, res) => {
      releasePoll = () => {
        releasePoll = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "old-flow-token", expires_in: 3600 }));
      };
      pollParked = true;
    };
    try {
      const fake = makeFakeEngine();
      const errors: unknown[] = [];
      const manager = fakeEngineManager(fake, {
        onBackgroundFlowError: (_secretId, err) => {
          errors.push(err);
        },
      });

      const first = await manager.startDeviceCode("gh", makeDeviceCodeConfig());
      await vi.waitFor(() => expect(pollParked).toBe(true));

      await manager.startDeviceCode("gh", makeDeviceCodeConfig());
      releasePoll();

      await expect(first.completion).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
      expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
      expect(errors).toHaveLength(0);
      expect(manager.cancelFlow("sid-1")).toBe(true);
    } finally {
      releasePoll();
    }
  });

  it("a device-code predecessor whose poll lands while the restart is still starting settles as superseded, silently", async () => {
    let deviceStarts = 0;
    let releaseDeviceStart: () => void = () => undefined;
    deviceHandler = (_req, res) => {
      deviceStarts += 1;
      const answer = (interval: number): void => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            device_code: `dc-${deviceStarts}`,
            user_code: "USER-1",
            verification_uri: "https://example.com/device",
            interval,
            expires_in: 600,
          }),
        );
      };
      if (deviceStarts === 1) {
        answer(0);
        return;
      }
      releaseDeviceStart = () => {
        releaseDeviceStart = () => undefined;
        answer(60);
      };
    };
    let pollParked = false;
    let releasePoll: () => void = () => undefined;
    tokenHandler = (_req, res) => {
      releasePoll = () => {
        releasePoll = () => undefined;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "old-flow-token", expires_in: 3600 }));
      };
      pollParked = true;
    };
    try {
      const fake = makeFakeEngine();
      const errors: unknown[] = [];
      const manager = fakeEngineManager(fake, {
        onBackgroundFlowError: (_secretId, err) => {
          errors.push(err);
        },
      });

      const first = await manager.startDeviceCode("gh", makeDeviceCodeConfig());
      await vi.waitFor(() => expect(pollParked).toBe(true));

      // The re-insert has happened, the successor's device request is still
      // out: the predecessor is superseded but not yet aborted.
      const second = manager.startDeviceCode("gh", makeDeviceCodeConfig());
      await vi.waitFor(() => expect(deviceStarts).toBe(2));
      releasePoll();

      await expect(first.completion).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
        message: "OAuth flow failed: OAuth flow superseded",
      });
      expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
      expect(errors).toHaveLength(0);

      releaseDeviceStart();
      await second;
      expect(manager.cancelFlow("sid-1")).toBe(true);
    } finally {
      releaseDeviceStart();
      releasePoll();
    }
  });

  it("a device-code restart whose start fails after the re-insert aborts the predecessor", async () => {
    let deviceStarts = 0;
    deviceHandler = (_req, res) => {
      deviceStarts += 1;
      if (deviceStarts > 1) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "server_error" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "dc-1",
          user_code: "USER-1",
          verification_uri: "https://example.com/device",
          interval: 60,
          expires_in: 600,
        }),
      );
    };
    const fake = makeFakeEngine();
    const errors: unknown[] = [];
    const manager = fakeEngineManager(fake, {
      onBackgroundFlowError: (_secretId, err) => {
        errors.push(err);
      },
    });

    const first = await manager.startDeviceCode("gh", makeDeviceCodeConfig());
    await expect(manager.startDeviceCode("gh", makeDeviceCodeConfig())).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });

    await expect(within(first.completion)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });
    expect(errors).toHaveLength(0);
    await vi.waitFor(() => {
      expect(manager.cancelFlow("sid-1")).toBe(false);
    });
    expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
  });

  it("a device-code start whose own device request is out when a later restart re-inserts the row never stores its tokens", async () => {
    let deviceStarts = 0;
    let releaseSecondStart: () => void = () => undefined;
    deviceHandler = (_req, res) => {
      deviceStarts += 1;
      const answer = (interval: number): void => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            device_code: `dc-${deviceStarts}`,
            user_code: "USER-1",
            verification_uri: "https://example.com/device",
            interval,
            expires_in: 600,
          }),
        );
      };
      if (deviceStarts === 2) {
        releaseSecondStart = () => {
          releaseSecondStart = () => undefined;
          answer(0);
        };
        return;
      }
      answer(60);
    };
    try {
      const fake = makeFakeEngine();
      const errors: unknown[] = [];
      const manager = fakeEngineManager(fake, {
        onBackgroundFlowError: (_secretId, err) => {
          errors.push(err);
        },
      });

      await manager.startDeviceCode("gh", makeDeviceCodeConfig());
      const pendingSecond = manager.startDeviceCode("gh", makeDeviceCodeConfig());
      await vi.waitFor(() => expect(deviceStarts).toBe(2));
      await manager.startDeviceCode("gh", makeDeviceCodeConfig());

      releaseSecondStart();
      const second = await pendingSecond;
      await expect(second.completion).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
      });
      expect(fake.completeOAuthFlow).not.toHaveBeenCalled();
      expect(errors).toHaveLength(0);
      expect(manager.cancelFlow("sid-1")).toBe(true);
    } finally {
      releaseSecondStart();
    }
  });

  it("a start refused by the cap after the re-insert aborts the predecessor", async () => {
    pendingDeviceCodeHandler();
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, maxPendingAuthorizations: 1 });

    const holder = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
    const device = await manager.startDeviceCode("b", makeDeviceCodeConfig());
    await expect(
      manager.startAuthorizationCodeDeferred("b", makeAuthCodeConfig()),
    ).rejects.toMatchObject({ code: ErrorCode.RATE_LIMIT_EXCEEDED });

    await expect(within(device.completion)).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });

    expect(manager.cancelFlow(holder.secretId)).toBe(true);
    await expect(holder.completion).rejects.toBeDefined();
  });

  it("a failed bind aborts its predecessor even after a later start took the slot", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0 });

    let releaseBind: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseBind = resolve;
    });
    const realStart = CallbackServer.prototype.start;
    let binds = 0;
    const startSpy = vi.spyOn(CallbackServer.prototype, "start").mockImplementation(async function (
      this: CallbackServer,
      state: string,
      timeoutMs?: number,
    ) {
      binds += 1;
      if (binds === 2) {
        await gate;
        throw new Error("EADDRINUSE");
      }
      return realStart.call(this, state, timeoutMs);
    });

    try {
      const first = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      const second = manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      await vi.waitFor(() => expect(startSpy).toHaveBeenCalledTimes(2));
      const third = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());

      releaseBind();
      await expect(second).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });

      await expect(within(first.completion)).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
      });

      expect(manager.cancelFlow("sid-a")).toBe(true);
      await expect(third.completion).rejects.toBeDefined();
    } finally {
      startSpy.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// Pending-flow cap (D3): concurrent socket-holding authorization-code flows
// ---------------------------------------------------------------------------

describe("OAuthManager pending-flow cap (D3)", () => {
  it("refuses an authorization-code start once the cap of socket-holding flows is reached", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, maxPendingAuthorizations: 2 });

    const a = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
    const b = await manager.startAuthorizationCodeDeferred("b", makeAuthCodeConfig());

    const refusal: unknown = await manager
      .startAuthorizationCodeDeferred("c", makeAuthCodeConfig())
      .catch((err: unknown) => err);

    expect(refusal).toBeInstanceOf(VaultError);
    const err = refusal as VaultError;
    expect(err.code).toBe(ErrorCode.RATE_LIMIT_EXCEEDED);
    expect(err.message).toContain("Too many pending authorization flows");
    expect(err.statusCode).toBe(429);

    manager.cancelPendingFlows();
    await expect(a.completion).rejects.toBeDefined();
    await expect(b.completion).rejects.toBeDefined();
  });

  it("floors a non-finite cap to the default rather than disabling it", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      maxPendingAuthorizations: Number.NaN,
    });

    // Every `count >= NaN` is false, so a NaN cap enforces nothing at all —
    // the one fail-open direction on this control.
    expect(
      (manager as unknown as { maxPendingAuthorizations: number }).maxPendingAuthorizations,
    ).toBe(DEFAULT_MAX_PENDING_AUTHORIZATIONS);

    // The fallback is a live cap, not a refuse-everything one.
    const a = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
    expect(a.handle).toBe("secret://a");

    manager.cancelPendingFlows();
    await expect(a.completion).rejects.toBeDefined();
  });

  it("a supersede for the same secret never trips the cap", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, maxPendingAuthorizations: 1 });

    const first = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
    // Same name → same secretId → the predecessor's listener is replaced, not
    // added to: one socket before, one socket after.
    const second = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
    expect(second.secretId).toBe(first.secretId);

    await expect(first.completion).rejects.toBeDefined();
    expect(manager.cancelFlow(second.secretId)).toBe(true);
    await expect(second.completion).rejects.toBeDefined();
  });

  it("a cancelled flow frees its slot", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, maxPendingAuthorizations: 1 });

    const a = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
    expect(manager.cancelFlow(a.secretId)).toBe(true);
    await expect(a.completion).rejects.toBeDefined();
    await vi.waitFor(() => {
      expect(manager.cancelFlow(a.secretId)).toBe(false);
    });

    const b = await manager.startAuthorizationCodeDeferred("b", makeAuthCodeConfig());
    expect(b.handle).toBe("secret://b");

    manager.cancelFlow(b.secretId);
    await expect(b.completion).rejects.toBeDefined();
  });

  it("device-code flows neither trip the cap nor count toward it", async () => {
    pendingDeviceCodeHandler();
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, maxPendingAuthorizations: 1 });

    // A device flow registers in the same map but holds no socket, so the one
    // authorization-code slot is still free...
    const device = await manager.startDeviceCode("d", makeDeviceCodeConfig());
    expect(device.status).toBe("pending_authorization");

    const a = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
    expect(a.handle).toBe("secret://a");

    // ...and with that slot taken, a further device flow is still not refused.
    const second = await manager.startDeviceCode("d2", makeDeviceCodeConfig());
    expect(second.status).toBe("pending_authorization");

    manager.cancelPendingFlows();
    await expect(a.completion).rejects.toBeDefined();
    await expect(device.completion).rejects.toBeDefined();
    await expect(second.completion).rejects.toBeDefined();
  });

  it("a refused start binds no callback socket (the PENDING secret stays resumable)", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, maxPendingAuthorizations: 1 });
    const startSpy = vi.spyOn(CallbackServer.prototype, "start");

    try {
      const a = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      expect(startSpy).toHaveBeenCalledTimes(1);

      await expect(
        manager.startAuthorizationCodeDeferred("b", makeAuthCodeConfig()),
      ).rejects.toBeDefined();

      // Refusal lands before any CallbackServer is constructed or started: no
      // second listener, no second timeout timer.
      expect(startSpy).toHaveBeenCalledTimes(1);
      // The vault row was created first, so the refused start leaves a
      // resumable PENDING secret (D3 — that is what `create` scope buys).
      expect(fake.createOAuthSecret).toHaveBeenCalledTimes(2);

      manager.cancelFlow(a.secretId);
      await expect(a.completion).rejects.toBeDefined();
    } finally {
      startSpy.mockRestore();
    }
  });

  it("counts a flow from before its bind, so a simultaneous burst cannot overshoot the cap", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, maxPendingAuthorizations: 1 });
    const { startSpy, releaseBind } = gateCallbackServerStart();

    try {
      const first = manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      // Let the first start reach its (gated) bind before the second is attempted.
      await vi.waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));

      const second: unknown = await manager
        .startAuthorizationCodeDeferred("b", makeAuthCodeConfig())
        .catch((err: unknown) => err);
      expect(second).toBeInstanceOf(VaultError);
      expect((second as VaultError).code).toBe(ErrorCode.RATE_LIMIT_EXCEEDED);
      expect(startSpy).toHaveBeenCalledTimes(1);

      releaseBind();
      const a = await first;
      manager.cancelFlow(a.secretId);
      await expect(a.completion).rejects.toBeDefined();
    } finally {
      startSpy.mockRestore();
    }
  });

  it("a cancelFlow during the bind window takes effect and releases the bound port (the reservation is the controller)", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0 });
    const { startSpy, releaseBind } = gateCallbackServerStart();

    try {
      const pending = manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      await vi.waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));
      expect(manager.cancelFlow("sid-a")).toBe(true);
      releaseBind();
      const a = await pending;
      await expect(a.completion).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
      const redirectUri = new URL(new URL(a.authUrl).searchParams.get("redirect_uri") as string);
      await vi.waitFor(async () => {
        await expect(
          fetch(`http://127.0.0.1:${redirectUri.port}/not-the-callback`),
        ).rejects.toThrow();
      });
    } finally {
      startSpy.mockRestore();
    }
  });

  it("a failed bind never resurrects a predecessor that settled inside the bind window", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, {
      callbackPort: 0,
      callbackTimeoutMs: 500,
      maxPendingAuthorizations: 1,
    });

    const first = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());

    let releaseBind: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseBind = resolve;
    });
    const startSpy = vi.spyOn(CallbackServer.prototype, "start").mockImplementation(async () => {
      await gate;
      throw new Error("EADDRINUSE");
    });

    try {
      // Same name → same secretId, so the successor's reservation replaces the
      // predecessor's entry: the predecessor's own callback timeout then
      // settles it without removing anything (the unregister is identity-guarded).
      const second = manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      await vi.waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));
      await expect(first.completion).rejects.toMatchObject({
        code: ErrorCode.OAUTH_CALLBACK_TIMEOUT,
      });

      releaseBind();
      await expect(second).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });

      // The failed bind leaves nothing dead behind: no entry to cancel...
      expect(manager.cancelFlow("sid-a")).toBe(false);
    } finally {
      startSpy.mockRestore();
    }

    // ...and the cap's single slot is free for the next flow.
    const b = await manager.startAuthorizationCodeDeferred("b", makeAuthCodeConfig());
    expect(b.handle).toBe("secret://b");
    manager.cancelFlow(b.secretId);
    await expect(b.completion).rejects.toBeDefined();
  });

  it("a failed bind after its own reservation was cancelled aborts the predecessor too", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0 });

    const first = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());

    let releaseBind: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseBind = resolve;
    });
    const startSpy = vi.spyOn(CallbackServer.prototype, "start").mockImplementation(async () => {
      await gate;
      throw new Error("EADDRINUSE");
    });

    try {
      // Same name → same secretId: the successor's reservation replaces the
      // predecessor's entry, so the predecessor is no longer in the map.
      const second = manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      await vi.waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));

      // The owner dispose path (DirectClient.close) lands inside the bind
      // window and aborts the only entry there — the reservation.
      manager.cancelPendingFlows();

      releaseBind();
      await expect(second).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });

      // The cancellation must cover the predecessor the reservation displaced:
      // restoring it would leave its callback server up past the dispose.
      await expect(within(first.completion)).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
      });

      expect(manager.cancelFlow("sid-a")).toBe(false);
    } finally {
      startSpy.mockRestore();
    }
  });

  it("a chained supersede whose middle bind fails still cancels the first flow", async () => {
    const fake = makePerNameFakeEngine();
    const manager = fakeEngineManager(fake, { callbackPort: 0, callbackTimeoutMs: 3_000 });

    let releaseBind: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseBind = resolve;
    });
    const realStart = CallbackServer.prototype.start;
    let binds = 0;
    const startSpy = vi.spyOn(CallbackServer.prototype, "start").mockImplementation(async function (
      this: CallbackServer,
      state: string,
      timeoutMs?: number,
    ) {
      binds += 1;
      if (binds === 2) {
        await gate;
        throw new Error("EADDRINUSE");
      }
      return realStart.call(this, state, timeoutMs);
    });

    try {
      // One name → one secretId → each start displaces the entry before it, so
      // the per-secret map only ever names the newest of the three.
      const first = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      const second = manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());
      await vi.waitFor(() => expect(startSpy).toHaveBeenCalledTimes(2));
      const third = await manager.startAuthorizationCodeDeferred("a", makeAuthCodeConfig());

      // The dispose lands while the second's bind is still held: the third's
      // bind aborted only the second, and the second's own exit — which would
      // abort the first — has not run, so the first is marked but live and
      // named by no map entry. Only the live set reaches it.
      manager.cancelPendingFlows();

      await expect(within(first.completion)).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
      });

      releaseBind();
      await expect(second).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });

      await expect(third.completion).rejects.toMatchObject({
        code: ErrorCode.OAUTH_FLOW_FAILED,
      });
    } finally {
      startSpy.mockRestore();
    }
  });
});
