import { describe, it, expect, vi } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { createApp } from "../app.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const ADMIN_TOKEN: VaultApiToken = {
  sub: "admin-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-admin",
  principal_type: "agent",
};

const USE_TOKEN: VaultApiToken = {
  ...ADMIN_TOKEN,
  sub: "use-agent",
  scope: ["use"],
  jti: "jti-use",
};

/** The caller the route must thread into the engine (`callerFromToken(token, "rest")`). */
const ADMIN_CALLER = {
  principal_type: "agent",
  principal_id: "admin-agent",
  interface: "rest",
  admin_scope: true,
};

/** A claim that scopes an admin token below the whole vault (N12, S3). */
const SCOPED_CLAIMS: Array<[string, Partial<VaultApiToken>]> = [
  ["project", { project: "acme" }],
  ["secrets", { secrets: ["*"] }],
];

const PATH = "/api/v1/vault/lock";
// Hono's in-process `app.request` sends no Host header; a default-built app
// checks one (R33/D9), so every request carries the loopback Host.
const HOST = { host: "localhost" };
const AUTH = { ...HOST, authorization: "Bearer valid-jwt" };

function createMockEngine(token: VaultApiToken = ADMIN_TOKEN) {
  return {
    verifyToken: vi.fn().mockReturnValue(token),
    auditScopeRefusal: vi.fn(),
    auditGovernanceRefusal: vi.fn(),
    lock: vi.fn().mockResolvedValue(undefined),
  };
}

function requestLock(engine: ReturnType<typeof createMockEngine>, init?: RequestInit) {
  return createApp(engine as never).request(PATH, { method: "POST", headers: AUTH, ...init });
}

describe("POST /api/v1/vault/lock", () => {
  it("locks the vault for an admin token, attributed to the token's principal", async () => {
    const engine = createMockEngine();

    const res = await requestLock(engine);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ data: { locked: true } });
    expect(engine.lock).toHaveBeenCalledTimes(1);
    expect(engine.lock).toHaveBeenCalledWith(ADMIN_CALLER);
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
    expect(engine.auditGovernanceRefusal).not.toHaveBeenCalled();
  });

  it("reads no body: a malformed JSON body is ignored, not refused", async () => {
    const engine = createMockEngine();

    const res = await requestLock(engine, {
      headers: { ...AUTH, "content-type": "application/json" },
      body: "{not json",
    });

    expect(res.status).toBe(200);
    expect(engine.lock).toHaveBeenCalledTimes(1);
  });

  it("refuses a use-only token 403 with one access.denied row before the lock", async () => {
    const engine = createMockEngine(USE_TOKEN);

    const res = await requestLock(engine);

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: ErrorCode.ACCESS_DENIED,
      message: "Access denied: Token lacks permission: admin",
    });
    expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
    expect(engine.auditScopeRefusal).toHaveBeenCalledWith(
      { principal_type: "agent", principal_id: "use-agent", interface: "rest" },
      "POST /api/v1/vault/lock",
      "permission",
    );
    expect(engine.lock).not.toHaveBeenCalled();
  });

  it("refuses a request without Authorization 401 INVALID_TOKEN: nothing locked, nothing recorded", async () => {
    const engine = createMockEngine();

    const res = await requestLock(engine, { headers: HOST });

    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe(ErrorCode.INVALID_TOKEN);
    expect(engine.verifyToken).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
    expect(engine.lock).not.toHaveBeenCalled();
  });

  it.each(SCOPED_CLAIMS)(
    "refuses a %s-claimed admin token 403 with one governance row before the lock: the lock is vault-wide",
    async (_claim, claims) => {
      const engine = createMockEngine({ ...ADMIN_TOKEN, ...claims });

      const res = await requestLock(engine);

      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({
        error: ErrorCode.ACCESS_DENIED,
        message: "Access denied: governance requires an unscoped admin token",
      });
      expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
      expect(engine.auditGovernanceRefusal).toHaveBeenCalledWith(
        { ...ADMIN_CALLER, ...claims },
        "POST /api/v1/vault/lock",
      );
      expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
      expect(engine.lock).not.toHaveBeenCalled();
    },
  );

  it("answers 503 VAULT_LOCKED at authentication once sealed: a second lock never reaches the route", async () => {
    const engine = createMockEngine();
    engine.verifyToken.mockImplementation(() => {
      throw VaultError.vaultLocked();
    });

    const res = await requestLock(engine);

    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: ErrorCode.VAULT_LOCKED, message: "Vault is locked" });
    expect(engine.lock).not.toHaveBeenCalled();
  });
});
