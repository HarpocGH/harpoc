import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VaultEngine } from "@harpoc/core";
import type { VaultApiToken } from "@harpoc/shared";
import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import {
  refuseEmptyToken,
  resolveTokenCaller,
  resolveTokenCallerForHandle,
} from "./token-caller.js";

function payload(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["use"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    principal_type: "agent",
    ...overrides,
  };
}

function engineWith(token: VaultApiToken) {
  return { verifyToken: vi.fn().mockReturnValue(token), auditScopeRefusal: vi.fn() };
}

describe("resolveTokenCaller", () => {
  it("returns undefined and never verifies when no token is supplied", () => {
    const engine = engineWith(payload());
    expect(
      resolveTokenCaller(engine, { permission: "use" }, undefined, "secret list"),
    ).toBeUndefined();
    expect(engine.verifyToken).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });

  it("refuses a present-but-empty token before verification", () => {
    const engine = engineWith(payload());
    expect(() => resolveTokenCaller(engine, { permission: "use" }, "  ", "secret list")).toThrow(
      "supplied but empty",
    );
    expect(engine.verifyToken).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });

  it("verifies, checks scope and builds the cli-attributed caller", () => {
    const engine = engineWith(payload({ scope: ["read"], project: "api" }));
    const resolved = resolveTokenCaller(
      engine,
      { permission: "read", project: "api", name: "db-key" },
      "jwt-value",
      "secret get",
    );
    expect(engine.verifyToken).toHaveBeenCalledWith("jwt-value");
    expect(resolved?.caller).toEqual({
      principal_type: "agent",
      principal_id: "agent-1",
      project: "api",
      interface: "cli",
    });
    expect(resolved?.payload.sub).toBe("agent-1");
  });

  it("enforces the permission dimension via the real shared predicate", async () => {
    const engine = engineWith(payload({ scope: ["use"] }));
    const err = await expectVaultError(
      () =>
        resolveTokenCaller(
          engine,
          { permission: "read", name: "db-key" },
          "jwt-value",
          "secret get",
        ),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe("Access denied: Token lacks permission: read");
  });

  it("enforces the project dimension", async () => {
    const engine = engineWith(payload({ scope: ["read"], project: "api" }));
    await expectVaultError(
      () =>
        resolveTokenCaller(
          engine,
          { permission: "read", project: "other", name: "k" },
          "jwt-value",
          "secret get",
        ),
      ErrorCode.ACCESS_DENIED,
    );
  });

  it("enforces the secret-name-pattern dimension", () => {
    const engine = engineWith(payload({ scope: ["read"], secrets: ["db-*"] }));
    expect(() =>
      resolveTokenCaller(
        engine,
        { permission: "read", name: "mail-key" },
        "jwt-value",
        "secret get",
      ),
    ).toThrow("does not grant access");
    expect(
      resolveTokenCaller(engine, { permission: "read", name: "db-key" }, "jwt-value", "secret get"),
    ).toBeDefined();
  });
});

describe("refuseEmptyToken", () => {
  it("passes undefined through and throws on whitespace", () => {
    expect(() => refuseEmptyToken(undefined)).not.toThrow();
    expect(() => refuseEmptyToken("")).toThrow("supplied but empty");
  });
});

describe("the empty-token refusal is INVALID_INPUT, its message unchanged (T4)", () => {
  it.each([
    { label: "refuseEmptyToken", call: () => refuseEmptyToken("") },
    {
      label: "resolveTokenCaller",
      call: () =>
        resolveTokenCaller(engineWith(payload()), { permission: "use" }, "  ", "secret list"),
    },
    {
      label: "resolveTokenCallerForHandle",
      call: () =>
        resolveTokenCallerForHandle(engineWith(payload()), "use", "secret://k", "  ", "secret use"),
    },
  ])("$label", async ({ call }) => {
    const err = await expectVaultError(call, ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(
      "--token (or HARPOC_TOKEN) was supplied but empty. Provide a token, or omit it entirely to use the trusted local path.",
    );
  });
});

describe("resolveTokenCallerForHandle", () => {
  // A malformed handle with NO token must not throw here: the engine parses
  // the handle itself so its `secret.use` denial audit row still gets
  // written, exactly as before token support existed.
  it("returns undefined and never verifies when no token is supplied, even with a malformed handle", () => {
    const engine = engineWith(payload());
    expect(
      resolveTokenCallerForHandle(engine, "use", "not-a-handle", undefined, "secret use"),
    ).toBeUndefined();
    expect(engine.verifyToken).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });

  it("refuses an empty token before checking handle validity", () => {
    const engine = engineWith(payload());
    expect(() =>
      resolveTokenCallerForHandle(engine, "use", "not-a-handle", "  ", "secret use"),
    ).toThrow("supplied but empty");
    expect(engine.verifyToken).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });

  it("parses a valid handle and matches resolveTokenCaller's result for the equivalent target", () => {
    const engine = engineWith(payload({ scope: ["use"], project: "api" }));
    const viaHandle = resolveTokenCallerForHandle(
      engine,
      "use",
      "secret://api/db-key",
      "jwt-value",
      "secret use",
    );

    const engine2 = engineWith(payload({ scope: ["use"], project: "api" }));
    const viaTarget = resolveTokenCaller(
      engine2,
      { permission: "use", project: "api", name: "db-key" },
      "jwt-value",
      "secret use",
    );

    expect(viaHandle).toEqual(viaTarget);
  });

  it("throws on a malformed handle with a present token, without ever verifying", async () => {
    const engine = engineWith(payload());
    await expectVaultError(
      () => resolveTokenCallerForHandle(engine, "use", "not-a-handle", "jwt-value", "secret use"),
      ErrorCode.INVALID_HANDLE,
    );
    expect(engine.verifyToken).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });
});

describe("a scope refusal writes the engine's access.denied row (A8)", () => {
  it.each([
    {
      reason: "permission",
      token: payload({ scope: ["use"] }),
      target: { permission: "read" as const, name: "db-key" },
      caller: { principal_type: "agent", principal_id: "agent-1", interface: "cli" },
    },
    {
      reason: "project",
      token: payload({ scope: ["read"], project: "api" }),
      target: { permission: "read" as const, project: "other", name: "db-key" },
      caller: {
        principal_type: "agent",
        principal_id: "agent-1",
        project: "api",
        interface: "cli",
      },
    },
    {
      reason: "secret",
      token: payload({ scope: ["read"], secrets: ["db-*"] }),
      target: { permission: "read" as const, name: "mail-key" },
      caller: {
        principal_type: "agent",
        principal_id: "agent-1",
        secrets: ["db-*"],
        interface: "cli",
      },
    },
  ])("$reason: once, with the token's caller and the command's path", async (row) => {
    const engine = engineWith(row.token);
    await expectVaultError(
      () => resolveTokenCaller(engine, row.target, "jwt-value", "secret get"),
      ErrorCode.ACCESS_DENIED,
    );
    expect(engine.auditScopeRefusal.mock.calls).toEqual([[row.caller, "secret get", row.reason]]);
  });

  it("the handle-addressed variant names its own command", async () => {
    const engine = engineWith(payload({ scope: ["read"], project: "api" }));
    await expectVaultError(
      () => resolveTokenCallerForHandle(engine, "use", "secret://api/db-key", "jwt", "secret use"),
      ErrorCode.ACCESS_DENIED,
    );
    expect(engine.auditScopeRefusal.mock.calls).toEqual([
      [
        { principal_type: "agent", principal_id: "agent-1", project: "api", interface: "cli" },
        "secret use",
        "permission",
      ],
    ]);
  });

  it("a token within its scope writes no row", () => {
    const engine = engineWith(payload({ scope: ["read"] }));
    resolveTokenCaller(engine, { permission: "read", name: "db-key" }, "jwt-value", "secret get");
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });

  it("a token that fails verification writes no row (U-7)", async () => {
    const engine = engineWith(payload());
    engine.verifyToken.mockImplementation(() => {
      throw VaultError.tokenExpired();
    });
    await expectVaultError(
      () => resolveTokenCaller(engine, { permission: "read" }, "jwt-value", "secret get"),
      ErrorCode.TOKEN_EXPIRED,
    );
    expect(engine.auditScopeRefusal).not.toHaveBeenCalled();
  });
});

describe("a scope refusal on a real engine (A8)", () => {
  let dir: string;
  let engine: VaultEngine;

  beforeEach(async () => {
    dir = join(tmpdir(), `harpoc-a8-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(dir, { recursive: true });
    engine = new VaultEngine({
      dbPath: join(dir, "vault.db"),
      sessionPath: join(dir, "session.json"),
    });
    await engine.initVault("test-password-123");
    engine.registerAgent({ name: "a8-agent" });
  });

  afterEach(async () => {
    await engine.destroy();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  function deniedRows() {
    return engine.queryAudit({ eventType: AuditEventType.ACCESS_DENIED });
  }

  it("a permission refusal leaves one access.denied row, interface cli", async () => {
    const jwt = engine.createToken("a8-agent", ["use"], 60_000, { project: "a8-proj" });
    await expectVaultError(
      () =>
        resolveTokenCallerForHandle(engine, "read", "secret://a8-proj/a8-name", jwt, "secret get"),
      ErrorCode.ACCESS_DENIED,
    );
    const rows = deniedRows();
    expect(rows).toHaveLength(1);
    const [row] = rows;
    expect({
      success: row?.success,
      secret_id: row?.secret_id,
      principal_type: row?.principal_type,
      principal_id: row?.principal_id,
      detail: row?.detail,
    }).toEqual({
      success: false,
      secret_id: null,
      principal_type: "agent",
      principal_id: "a8-agent",
      detail: {
        operation: "secret get",
        error: "ACCESS_DENIED",
        reason: "permission",
        interface: "cli",
      },
    });
    expect(JSON.stringify(row).includes("a8-name")).toBe(false);
    expect(JSON.stringify(row).includes("a8-proj")).toBe(false);
    expect(JSON.stringify(row).includes(jwt)).toBe(false);
  });

  it("secret list's cross-project refusal leaves one access.denied row, interface cli", async () => {
    const jwt = engine.createToken("a8-agent", ["list"], 60_000, { project: "a8-proj" });
    const err = await expectVaultError(
      () =>
        resolveTokenCaller(
          engine,
          { permission: "list", project: "a8-elsewhere" },
          jwt,
          "secret list",
        ),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe("Access denied: Token is scoped to project: a8-proj");
    const rows = deniedRows();
    expect(rows.map((row) => ({ principal_id: row.principal_id, detail: row.detail }))).toEqual([
      {
        principal_id: "a8-agent",
        detail: {
          operation: "secret list",
          error: "ACCESS_DENIED",
          reason: "project",
          interface: "cli",
        },
      },
    ]);
    expect(JSON.stringify(rows[0]).includes("a8-elsewhere")).toBe(false);
    expect(JSON.stringify(rows[0]).includes(jwt)).toBe(false);
  });

  it("a name-pattern refusal leaves one access.denied row, interface cli, no pattern in it", async () => {
    const jwt = engine.createToken("a8-agent", ["read"], 60_000, { secrets: ["a8-db-*"] });
    await expectVaultError(
      () => resolveTokenCallerForHandle(engine, "read", "secret://a8-name", jwt, "secret get"),
      ErrorCode.ACCESS_DENIED,
    );
    const rows = deniedRows();
    expect(rows.map((row) => ({ principal_id: row.principal_id, detail: row.detail }))).toEqual([
      {
        principal_id: "a8-agent",
        detail: {
          operation: "secret get",
          error: "ACCESS_DENIED",
          reason: "secret",
          interface: "cli",
        },
      },
    ]);
    expect(JSON.stringify(rows[0]).includes("a8-db-")).toBe(false);
    expect(JSON.stringify(rows[0]).includes("a8-name")).toBe(false);
    expect(JSON.stringify(rows[0]).includes(jwt)).toBe(false);
  });
});
