import { describe, expect, it, vi } from "vitest";
import type { VaultApiToken } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
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
  return { verifyToken: vi.fn().mockReturnValue(token) };
}

describe("resolveTokenCaller", () => {
  it("returns undefined and never verifies when no token is supplied", () => {
    const engine = engineWith(payload());
    expect(resolveTokenCaller(engine, { permission: "use" }, undefined)).toBeUndefined();
    expect(engine.verifyToken).not.toHaveBeenCalled();
  });

  it("refuses a present-but-empty token before verification", () => {
    const engine = engineWith(payload());
    expect(() => resolveTokenCaller(engine, { permission: "use" }, "  ")).toThrow(
      "supplied but empty",
    );
    expect(engine.verifyToken).not.toHaveBeenCalled();
  });

  it("verifies, checks scope and builds the cli-attributed caller", () => {
    const engine = engineWith(payload({ scope: ["read"], project: "api" }));
    const resolved = resolveTokenCaller(
      engine,
      { permission: "read", project: "api", name: "db-key" },
      "jwt-value",
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

  it("enforces the permission dimension via the real shared predicate", () => {
    const engine = engineWith(payload({ scope: ["use"] }));
    expect(() =>
      resolveTokenCaller(engine, { permission: "read", name: "db-key" }, "jwt-value"),
    ).toThrow("Token lacks permission: read");
  });

  it("enforces the project dimension", async () => {
    const engine = engineWith(payload({ scope: ["read"], project: "api" }));
    await expectVaultError(
      () =>
        resolveTokenCaller(
          engine,
          { permission: "read", project: "other", name: "k" },
          "jwt-value",
        ),
      ErrorCode.ACCESS_DENIED,
    );
  });

  it("enforces the secret-name-pattern dimension", () => {
    const engine = engineWith(payload({ scope: ["read"], secrets: ["db-*"] }));
    expect(() =>
      resolveTokenCaller(engine, { permission: "read", name: "mail-key" }, "jwt-value"),
    ).toThrow("does not grant access");
    expect(
      resolveTokenCaller(engine, { permission: "read", name: "db-key" }, "jwt-value"),
    ).toBeDefined();
  });
});

describe("refuseEmptyToken", () => {
  it("passes undefined through and throws on whitespace", () => {
    expect(() => refuseEmptyToken(undefined)).not.toThrow();
    expect(() => refuseEmptyToken("")).toThrow("supplied but empty");
  });
});

describe("resolveTokenCallerForHandle", () => {
  // A malformed handle with NO token must not throw here: the engine parses
  // the handle itself so its `secret.use` denial audit row still gets
  // written, exactly as before token support existed.
  it("returns undefined and never verifies when no token is supplied, even with a malformed handle", () => {
    const engine = engineWith(payload());
    expect(resolveTokenCallerForHandle(engine, "use", "not-a-handle", undefined)).toBeUndefined();
    expect(engine.verifyToken).not.toHaveBeenCalled();
  });

  it("refuses an empty token before checking handle validity", () => {
    const engine = engineWith(payload());
    expect(() => resolveTokenCallerForHandle(engine, "use", "not-a-handle", "  ")).toThrow(
      "supplied but empty",
    );
    expect(engine.verifyToken).not.toHaveBeenCalled();
  });

  it("parses a valid handle and matches resolveTokenCaller's result for the equivalent target", () => {
    const engine = engineWith(payload({ scope: ["use"], project: "api" }));
    const viaHandle = resolveTokenCallerForHandle(
      engine,
      "use",
      "secret://api/db-key",
      "jwt-value",
    );

    const engine2 = engineWith(payload({ scope: ["use"], project: "api" }));
    const viaTarget = resolveTokenCaller(
      engine2,
      { permission: "use", project: "api", name: "db-key" },
      "jwt-value",
    );

    expect(viaHandle).toEqual(viaTarget);
  });

  it("throws on a malformed handle with a present token, without ever verifying", () => {
    const engine = engineWith(payload());
    expect(() => resolveTokenCallerForHandle(engine, "use", "not-a-handle", "jwt-value")).toThrow();
    expect(engine.verifyToken).not.toHaveBeenCalled();
  });
});
