import { afterAll, afterEach, beforeAll, beforeEach, describe, it, expect, vi } from "vitest";
import {
  RATE_LIMIT_GLOBAL,
  RATE_LIMIT_PER_SECRET,
  RATE_LIMIT_USE_SECRET,
  VaultState,
} from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { createApp } from "../app.js";

/**
 * T8 (REST half): rate limiting was enforced nowhere in the tests — removing
 * all four `app.use(createRateLimitMiddleware(...))` registrations and all
 * five `limiter.checkSecret(...)` calls left rest-api fully green, because the
 * route suites build their own app without the middleware. These cases drive
 * the real `createApp`, so both halves of the wiring are load-bearing.
 */

const MOCK_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
};

const AUTH = { authorization: "Bearer valid" };

function createMockEngine() {
  return {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    verifyToken: vi.fn().mockReturnValue(MOCK_TOKEN),
    listSecrets: vi.fn().mockReturnValue([]),
    getSecretInfo: vi.fn().mockResolvedValue({
      handle: "secret://k",
      name: "k",
      type: "api_key",
      project: null,
      status: "active",
      version: 1,
      createdAt: 1000,
      updatedAt: 1000,
      expiresAt: null,
      rotatedAt: null,
    }),
    useSecret: vi.fn().mockResolvedValue({ type: "http", status: 200 }),
    resolveSecretId: vi.fn().mockResolvedValue("uuid-1"),
    queryAudit: vi.fn().mockReturnValue([]),
    getOAuthTokenStatus: vi.fn().mockReturnValue({ secret_id: "uuid-1" }),
    getCertificateStatus: vi.fn().mockReturnValue({ secret_id: "uuid-1" }),
    listAgents: vi.fn().mockReturnValue([]),
    getAgent: vi.fn().mockReturnValue({ id: "agent-1", name: "x", status: "active" }),
    listIssuedTokens: vi.fn().mockReturnValue([]),
  };
}

function app() {
  return createApp(createMockEngine() as never);
}

/** Repeats a request `times` times and returns the status of the last one. */
async function hammer(
  instance: ReturnType<typeof app>,
  path: string,
  times: number,
  init?: RequestInit,
): Promise<number> {
  let status = 0;
  for (let i = 0; i < times; i++) {
    const res = await instance.request(path, init ?? { headers: AUTH });
    status = res.status;
  }
  return status;
}

// The audit middleware writes a line per request; these cases make thousands.
let debugSpy: ReturnType<typeof vi.spyOn>;
beforeAll(() => {
  debugSpy = vi.spyOn(console, "debug").mockImplementation(() => undefined);
});
afterAll(() => {
  debugSpy.mockRestore();
});

// The bucket refills continuously (limit/minute), so a thousand-request loop
// hands back a token every 60 ms of wall clock — enough to make an exact
// boundary assertion depend on machine speed. The clock is frozen for the
// duration: the property under test is enforcement, not decay.
beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: false });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("REST rate limiting is enforced on the wired app (T8)", () => {
  it("the global tier bounds an authenticated route", async () => {
    const instance = app();

    expect(await hammer(instance, "/api/v1/audit", RATE_LIMIT_GLOBAL)).toBe(200);

    const overflow = await instance.request("/api/v1/audit", { headers: AUTH });
    expect(overflow.status).toBe(429);
    const body = (await overflow.json()) as { error?: string };
    expect(body.error).toBe("RATE_LIMIT_EXCEEDED");
  });

  /**
   * The collection route spends exactly one token per request. It used to
   * spend two: `/api/v1/secrets/*` already matches the bare path, so the extra
   * `/api/v1/secrets` registration ran every middleware on it a second time and
   * the route ran out at half its allowance.
   */
  it("the collection route spends exactly one global token per request", async () => {
    const instance = app();
    let served = 0;
    for (;;) {
      const res = await instance.request("/api/v1/secrets", { headers: AUTH });
      if (res.status === 429) break;
      served++;
      if (served > RATE_LIMIT_GLOBAL) break;
    }

    expect(served).toBe(RATE_LIMIT_GLOBAL);
  });

  it("the per-secret tier bounds a single handle well before the global one", async () => {
    const instance = app();

    expect(await hammer(instance, "/api/v1/secrets/k", RATE_LIMIT_PER_SECRET)).toBe(200);

    const overflow = await instance.request("/api/v1/secrets/k", { headers: AUTH });
    expect(overflow.status).toBe(429);
    // Well below the global allowance: this is the per-secret bucket talking.
    expect(RATE_LIMIT_PER_SECRET + 1).toBeLessThan(RATE_LIMIT_GLOBAL);
  });

  /**
   * T10 (REST half): the route's own `limiter.checkSecret(...)` call runs
   * regardless of whether `createRateLimitMiddleware` is registered for the
   * prefix — it would still 429 a lone handle hammered past
   * `RATE_LIMIT_PER_SECRET` even with the `app.use(...)` registration
   * deleted, so a per-secret hammer proves nothing about that registration.
   * What the registration alone controls is the *global* bucket: draining it
   * through an unrelated route only 429s these two routes next if they still
   * run through `createRateLimitMiddleware`. Guard-flip-verified: deleting
   * the `/api/v1/certificates/*` registration in app.ts turns this red
   * (200, not 429) and was restored after confirming that; the v1.4
   * `/api/v1/agents/*` and `/api/v1/tokens/*` registrations were verified the
   * same way.
   */
  it("draining the global bucket 429s the OAuth, certificates, agents and tokens routes", async () => {
    const instance = app();

    expect(await hammer(instance, "/api/v1/secrets", RATE_LIMIT_GLOBAL)).toBe(200);

    const oauthOverflow = await instance.request("/api/v1/oauth/k/status", { headers: AUTH });
    expect(oauthOverflow.status).toBe(429);

    const certOverflow = await instance.request("/api/v1/certificates/k/status", {
      headers: AUTH,
    });
    expect(certOverflow.status).toBe(429);

    const agentsOverflow = await instance.request("/api/v1/agents", { headers: AUTH });
    expect(agentsOverflow.status).toBe(429);

    const tokensOverflow = await instance.request("/api/v1/tokens", { headers: AUTH });
    expect(tokensOverflow.status).toBe(429);
  });

  it("use carries its own, higher tier", async () => {
    const instance = app();
    const post = {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/json" },
      body: JSON.stringify({
        action: {
          type: "http",
          method: "GET",
          url: "https://api.example.com/ping",
          injection: { type: "bearer" },
        },
      }),
    };

    // Past the ordinary per-secret bound, still fine: `use` has its own bucket.
    expect(await hammer(instance, "/api/v1/secrets/k/use", RATE_LIMIT_USE_SECRET, post)).toBe(200);

    const overflow = await instance.request("/api/v1/secrets/k/use", post);
    expect(overflow.status).toBe(429);
  });

  it("control: the unauthenticated health route is exempt", async () => {
    const instance = app();
    await hammer(instance, "/api/v1/secrets", RATE_LIMIT_GLOBAL + 1);

    // Global bucket is empty, yet health still answers — it is registered
    // before the limiter and must stay reachable for liveness probes.
    const res = await instance.request("/api/v1/health");
    expect(res.status).toBe(200);
  });

  it("control: a fresh app starts with a full bucket", async () => {
    const instance = app();
    const res = await instance.request("/api/v1/secrets", { headers: AUTH });
    expect(res.status).toBe(200);
  });

  /**
   * The same overlap that double-charged the limiter also ran the audit and
   * auth middleware twice per collection request — one audit line per request
   * is what the trail is read as, and one token verification is what a rate
   * limit is meant to bound. Asserted on the two observable effects.
   */
  it.each([
    ["/api/v1/secrets", "collection"],
    ["/api/v1/secrets/k", "item"],
    ["/api/v1/agents", "agent collection"],
    ["/api/v1/agents/x", "agent item"],
    ["/api/v1/tokens", "token collection"],
  ])("each middleware runs once per request on the %s route (%s)", async (path) => {
    const engine = createMockEngine();
    const instance = createApp(engine as never);
    debugSpy.mockClear();

    await instance.request(path, { headers: AUTH });

    expect(engine.verifyToken).toHaveBeenCalledTimes(1);
    expect(debugSpy).toHaveBeenCalledTimes(1);
  });
});
