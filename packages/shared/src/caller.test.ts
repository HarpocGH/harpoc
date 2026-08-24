import { describe, expect, it } from "vitest";
import { callerFromToken, checkTokenScope, isAdminUserCaller } from "./caller.js";
import { ErrorCode } from "./errors.js";
import type { VaultApiToken } from "./types.js";
import { TokenPrincipalType } from "./types.js";

function baseToken(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "alice",
    vault_id: "vault-1",
    scope: ["use"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    ...overrides,
  };
}

describe("callerFromToken", () => {
  it("defaults an absent principal_type claim to agent (legacy tokens)", () => {
    const caller = callerFromToken(baseToken());
    expect(caller).toEqual({ principal_type: "agent", principal_id: "alice" });
  });

  it("carries each issuable principal type through", () => {
    for (const type of Object.values(TokenPrincipalType)) {
      const caller = callerFromToken(baseToken({ principal_type: type }));
      expect(caller.principal_type).toBe(type);
      expect(caller.principal_id).toBe("alice");
    }
  });

  it("passes the project claim through for project-principal derivation", () => {
    const caller = callerFromToken(baseToken({ project: "api" }));
    expect(caller.project).toBe("api");
  });

  it("omits the project key entirely when the token has no project claim", () => {
    const caller = callerFromToken(baseToken());
    expect("project" in caller).toBe(false);
  });

  it("TokenPrincipalType has 3 members and excludes project", () => {
    expect(Object.values(TokenPrincipalType)).toHaveLength(3);
    expect(Object.values(TokenPrincipalType)).not.toContain("project");
  });

  it("carries the access interface through when provided", () => {
    for (const iface of ["rest", "mcp", "mcp-http", "cli"] as const) {
      const caller = callerFromToken(baseToken(), iface);
      expect(caller.interface).toBe(iface);
      expect(caller.principal_id).toBe("alice");
    }
  });

  it("omits the interface key entirely when no interface is given", () => {
    const caller = callerFromToken(baseToken());
    expect("interface" in caller).toBe(false);
  });
});

// Relocated from rest-api (Phase 3 T1) so the CLI token path shares the exact
// REST semantics; these are the predicate's first direct unit tests.
describe("checkTokenScope", () => {
  function denied(fn: () => void): void {
    try {
      fn();
    } catch (err) {
      expect((err as { code?: string }).code).toBe(ErrorCode.ACCESS_DENIED);
      return;
    }
    throw new Error("expected ACCESS_DENIED, but the check passed");
  }

  it("passes when the token holds the exact permission", () => {
    expect(() => checkTokenScope(baseToken({ scope: ["use"] }), "use")).not.toThrow();
  });

  it("denies a permission the token does not hold", () => {
    denied(() => checkTokenScope(baseToken({ scope: ["read"] }), "use"));
  });

  it("admin implies every permission", () => {
    for (const perm of ["use", "read", "rotate", "list", "revoke", "create"] as const) {
      expect(() => checkTokenScope(baseToken({ scope: ["admin"] }), perm)).not.toThrow();
    }
  });

  it("project-scoped token passes on its own project", () => {
    expect(() =>
      checkTokenScope(baseToken({ project: "api" }), "use", "api", "db-main"),
    ).not.toThrow();
  });

  it("project-scoped token is denied on another project", () => {
    denied(() => checkTokenScope(baseToken({ project: "api" }), "use", "web", "db-main"));
  });

  it("project-scoped token is denied on a global (project-less) secret", () => {
    denied(() => checkTokenScope(baseToken({ project: "api" }), "use", undefined, "db-main"));
  });

  it("unrestricted token passes on any project", () => {
    expect(() => checkTokenScope(baseToken(), "use", "web", "db-main")).not.toThrow();
  });

  it("name patterns gate the secret dimension (full-anchored, * wildcard)", () => {
    const token = baseToken({ secrets: ["db-*"] });
    expect(() => checkTokenScope(token, "use", undefined, "db-main")).not.toThrow();
    denied(() => checkTokenScope(token, "use", undefined, "api-key"));
    denied(() => checkTokenScope(token, "use", undefined, "xdb-main"));
  });

  it("absent or empty secrets claim leaves the name dimension unrestricted", () => {
    expect(() => checkTokenScope(baseToken(), "use", undefined, "anything")).not.toThrow();
    expect(() =>
      checkTokenScope(baseToken({ secrets: [] }), "use", undefined, "anything"),
    ).not.toThrow();
  });

  it("permission-only calls skip the project and name dimensions", () => {
    expect(() => checkTokenScope(baseToken({ project: "api" }), "use")).not.toThrow();
  });
});

describe("admin_scope (R7)", () => {
  it("callerFromToken sets admin_scope when the scope claim includes admin", () => {
    const caller = callerFromToken(baseToken({ scope: ["admin"], principal_type: "user" }));
    expect(caller.admin_scope).toBe(true);
  });

  it("callerFromToken omits admin_scope for a non-admin scope", () => {
    const caller = callerFromToken(
      baseToken({ scope: ["read", "rotate"], principal_type: "user" }),
    );
    expect("admin_scope" in caller).toBe(false);
  });

  it("isAdminUserCaller: true only for user-type callers carrying the flag", () => {
    expect(
      isAdminUserCaller(callerFromToken(baseToken({ scope: ["admin"], principal_type: "user" }))),
    ).toBe(true);
    // absent type = agent
    expect(isAdminUserCaller(callerFromToken(baseToken({ scope: ["admin"] })))).toBe(false);
    expect(
      isAdminUserCaller(callerFromToken(baseToken({ scope: ["admin"], principal_type: "agent" }))),
    ).toBe(false);
    expect(
      isAdminUserCaller(callerFromToken(baseToken({ scope: ["admin"], principal_type: "tool" }))),
    ).toBe(false);
    expect(
      isAdminUserCaller(callerFromToken(baseToken({ scope: ["read"], principal_type: "user" }))),
    ).toBe(false);
  });

  it("isAdminUserCaller ignores a hand-built caller without the flag", () => {
    expect(isAdminUserCaller({ principal_type: "user", principal_id: "x" })).toBe(false);
  });
});
