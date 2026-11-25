import { describe, expect, it, vi } from "vitest";
import {
  agentSocketCaller,
  auditScopeFromToken,
  callerFromToken,
  checkTokenScope,
  isAdminUserCaller,
  TOKENLESS_STDIO_PRINCIPAL,
  tokenlessStdioCaller,
  tokenScopeRefusal,
} from "./caller.js";
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
    principal_type: "agent",
    ...overrides,
  };
}

describe("callerFromToken", () => {
  it("carries the token's principal_type claim through verbatim", () => {
    expect(callerFromToken(baseToken())).toEqual({
      principal_type: "agent",
      principal_id: "alice",
    });
    expect(callerFromToken(baseToken({ principal_type: "user" })).principal_type).toBe("user");
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

  it("carries the access interface through when provided", () => {
    for (const iface of ["rest", "mcp", "mcp-http", "cli", "proxy", "ssh_agent"] as const) {
      const caller = callerFromToken(baseToken(), iface);
      expect(caller.interface).toBe(iface);
      expect(caller.principal_id).toBe("alice");
    }
  });

  it("omits the interface key entirely when no interface is given", () => {
    const caller = callerFromToken(baseToken());
    expect("interface" in caller).toBe(false);
  });

  it('carries a non-empty secrets claim through, ["*"] included, for the governance refusal (S3)', () => {
    expect(callerFromToken(baseToken({ secrets: ["db-*"] }))).toEqual({
      principal_type: "agent",
      principal_id: "alice",
      secrets: ["db-*"],
    });
    expect(callerFromToken(baseToken({ secrets: ["*"] })).secrets).toEqual(["*"]);
  });

  it("omits the secrets key entirely when the claim is absent or empty", () => {
    expect("secrets" in callerFromToken(baseToken())).toBe(false);
    expect("secrets" in callerFromToken(baseToken({ secrets: [] }))).toBe(false);
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

  it("admin stays bound to its project", () => {
    denied(() =>
      checkTokenScope(baseToken({ scope: ["admin"], project: "api" }), "use", "web", "db-main"),
    );
  });

  it("admin stays bound to its secret-name patterns", () => {
    denied(() =>
      checkTokenScope(
        baseToken({ scope: ["admin"], secrets: ["db-*"] }),
        "use",
        undefined,
        "api-key",
      ),
    );
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

describe("tokenScopeRefusal", () => {
  it("a token without project or name claims admits every handle", () => {
    expect(tokenScopeRefusal({}, undefined, "a")).toBeUndefined();
    expect(tokenScopeRefusal({}, "p", "a")).toBeUndefined();
    expect(tokenScopeRefusal({}, undefined, undefined)).toBeUndefined();
  });

  it("a project claim refuses another project and a project-less secret as project", () => {
    const scope = { project: "acme" };
    expect(tokenScopeRefusal(scope, "other", "db")).toBe("project");
    expect(tokenScopeRefusal(scope, undefined, "db")).toBe("project");
    expect(tokenScopeRefusal(scope, "other", undefined)).toBe("project");
    expect(tokenScopeRefusal(scope, "acme", "db")).toBeUndefined();
    expect(tokenScopeRefusal(scope, undefined, undefined)).toBeUndefined();
  });

  it("name patterns refuse a name outside them as secret", () => {
    const scope = { secrets: ["db-*"] };
    expect(tokenScopeRefusal(scope, undefined, "db-main")).toBeUndefined();
    expect(tokenScopeRefusal(scope, undefined, "api-key")).toBe("secret");
    expect(tokenScopeRefusal(scope, undefined, "xdb-main")).toBe("secret");
    expect(tokenScopeRefusal(scope, undefined, undefined)).toBeUndefined();
    expect(tokenScopeRefusal({ secrets: [] }, undefined, "anything")).toBeUndefined();
    expect(tokenScopeRefusal({ secrets: ["*"] }, undefined, "anything")).toBeUndefined();
  });

  it("the project branch answers before the name branch", () => {
    expect(tokenScopeRefusal({ project: "acme", secrets: ["db-*"] }, "other", "api-key")).toBe(
      "project",
    );
  });

  it("a caller derived from a token answers as the token", () => {
    const tokens = [
      baseToken(),
      baseToken({ project: "acme" }),
      baseToken({ project: "" }),
      baseToken({ secrets: [] }),
      baseToken({ secrets: ["db-*"] }),
      baseToken({ project: "acme", secrets: ["*"] }),
    ];
    const targets: [string | undefined, string | undefined][] = [
      ["acme", "db-1"],
      ["other", "db-1"],
      [undefined, "db-1"],
      [undefined, "x"],
      [undefined, undefined],
    ];
    for (const token of tokens) {
      for (const [project, name] of targets) {
        const label = JSON.stringify({
          project: token.project,
          secrets: token.secrets,
          project_arg: project,
          name,
        });
        expect(tokenScopeRefusal(callerFromToken(token), project, name), label).toBe(
          tokenScopeRefusal(token, project, name),
        );
      }
    }
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

describe("tokenlessStdioCaller (R4/E78b)", () => {
  it("is a user-type, admin-scoped caller named tokenless-stdio on the given interface", () => {
    expect(tokenlessStdioCaller("mcp")).toEqual({
      principal_type: "user",
      principal_id: TOKENLESS_STDIO_PRINCIPAL,
      interface: "mcp",
      admin_scope: true,
    });
    expect(TOKENLESS_STDIO_PRINCIPAL).toBe("tokenless-stdio");
  });

  it("is exempt exactly like an admin-scoped user token (R7)", () => {
    expect(isAdminUserCaller(tokenlessStdioCaller("mcp"))).toBe(true);
  });
});

describe("agentSocketCaller (B3)", () => {
  it("is the consumer as an agent-type principal on the ssh_agent interface, and nothing else", () => {
    const caller = agentSocketCaller("ci-bot");
    expect(caller).toEqual({
      principal_type: "agent",
      principal_id: "ci-bot",
      interface: "ssh_agent",
    });
    expect(Object.keys(caller).sort()).toEqual(["interface", "principal_id", "principal_type"]);
  });

  it("is never exempt from the per-secret grants (R7): no admin_scope, not an admin user", () => {
    const caller = agentSocketCaller("ci-bot");
    expect("admin_scope" in caller).toBe(false);
    expect(isAdminUserCaller(caller)).toBe(false);
  });
});

describe("remote_address (E75i)", () => {
  it("callerFromToken carries a supplied socket peer", () => {
    expect(callerFromToken(baseToken(), "rest", "10.0.0.7").remote_address).toBe("10.0.0.7");
  });

  it("omits the remote_address key entirely when none is supplied", () => {
    expect("remote_address" in callerFromToken(baseToken(), "rest")).toBe(false);
    expect("remote_address" in callerFromToken(baseToken(), "rest", undefined)).toBe(false);
    expect("remote_address" in callerFromToken(baseToken(), "rest", "")).toBe(false);
  });
});

describe("checkTokenScope — onRefusal (D2g)", () => {
  const base = baseToken({ sub: "agent-1", scope: ["read", "list"] });

  it("reports the permission branch once, then throws", () => {
    const seen = vi.fn();
    expect(() => checkTokenScope(base, "rotate", undefined, undefined, seen)).toThrow(
      expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
    );
    expect(seen).toHaveBeenCalledTimes(1);
    expect(seen).toHaveBeenCalledWith("permission");
  });

  it("reports a cross-project refusal and a global-secret refusal as project", () => {
    const scoped = { ...base, project: "acme" };
    const seen = vi.fn();
    expect(() => checkTokenScope(scoped, "read", "other", "db", seen)).toThrow();
    expect(() => checkTokenScope(scoped, "read", undefined, "db", seen)).toThrow();
    expect(seen.mock.calls).toEqual([["project"], ["project"]]);
  });

  it("reports the secret-name branch as secret", () => {
    const seen = vi.fn();
    expect(() =>
      checkTokenScope({ ...base, secrets: ["db-*"] }, "read", undefined, "mail", seen),
    ).toThrow();
    expect(seen).toHaveBeenCalledWith("secret");
  });

  it("an admitted call never invokes it", () => {
    const seen = vi.fn();
    checkTokenScope(base, "read", undefined, "db", seen);
    expect(seen).not.toHaveBeenCalled();
  });

  it("keeps its three texts", () => {
    const deniedWith = (message: string) =>
      expect.objectContaining({ code: ErrorCode.ACCESS_DENIED, message });
    expect(() => checkTokenScope(base, "rotate")).toThrow(
      deniedWith("Access denied: Token lacks permission: rotate"),
    );
    const scoped = { ...base, project: "acme" };
    expect(() => checkTokenScope(scoped, "read", "other", "db")).toThrow(
      deniedWith("Access denied: Token is scoped to project: acme"),
    );
    expect(() => checkTokenScope(scoped, "read", undefined, "db")).toThrow(
      deniedWith("Access denied: Token is scoped to project: acme"),
    );
    expect(() =>
      checkTokenScope({ ...base, secrets: ["db-*"] }, "read", undefined, "mail"),
    ).toThrow(deniedWith("Access denied: Token does not grant access to this secret"));
  });
});

describe("auditScopeFromToken", () => {
  it('copies the secrets claim by the ?.length rule: absent or [] is no scope, ["*"] scopes', () => {
    expect(auditScopeFromToken(baseToken())).toBeUndefined();
    expect(auditScopeFromToken(baseToken({ secrets: [] }))).toBeUndefined();
    expect(auditScopeFromToken(baseToken({ secrets: ["*"] }))).toEqual({ secrets: ["*"] });
  });
});
