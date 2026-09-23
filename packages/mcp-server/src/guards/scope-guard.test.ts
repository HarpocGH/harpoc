import { describe, it, expect, vi } from "vitest";
import type { VaultApiToken } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { ScopeGuard } from "./scope-guard.js";

function makeToken(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "test-agent",
    vault_id: "vault-123",
    scope: ["use", "list"],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-123",
    principal_type: "agent",
    ...overrides,
  };
}

describe("ScopeGuard", () => {
  describe("null token (full access)", () => {
    it("allows any permission", () => {
      const guard = new ScopeGuard(null);
      expect(() => guard.checkAccess("use")).not.toThrow();
      expect(() => guard.checkAccess("create")).not.toThrow();
      expect(() => guard.checkAccess("admin")).not.toThrow();
    });
  });

  describe("permission enforcement", () => {
    it("allows permitted actions", () => {
      const guard = new ScopeGuard(makeToken({ scope: ["use", "list"] }));
      expect(() => guard.checkAccess("use")).not.toThrow();
      expect(() => guard.checkAccess("list")).not.toThrow();
    });

    it("denies unpermitted actions", () => {
      const guard = new ScopeGuard(makeToken({ scope: ["use", "list"] }));
      expect(() => guard.checkAccess("create")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("admin implies all permissions", () => {
      const guard = new ScopeGuard(makeToken({ scope: ["admin"] }));
      expect(() => guard.checkAccess("use")).not.toThrow();
      expect(() => guard.checkAccess("create")).not.toThrow();
      expect(() => guard.checkAccess("revoke")).not.toThrow();
    });
  });

  describe("project scoping", () => {
    it("allows access to matching project", () => {
      const guard = new ScopeGuard(makeToken({ project: "my-project" }));
      expect(() => guard.checkAccess("use", "my-project")).not.toThrow();
    });

    it("denies access to different project", () => {
      const guard = new ScopeGuard(makeToken({ project: "my-project" }));
      expect(() => guard.checkAccess("use", "other-project")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("allows listing without project context", () => {
      const guard = new ScopeGuard(makeToken({ project: "my-project" }));
      // No project in the access check — allowed for listing (no secretName)
      expect(() => guard.checkAccess("use")).not.toThrow();
    });

    it("denies individual access to global (project-less) secrets", () => {
      const guard = new ScopeGuard(makeToken({ project: "my-project" }));
      // Secret with no project accessed individually (secretName provided)
      expect(() => guard.checkAccess("use", undefined, "global-key")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("allows when token has no project scope", () => {
      const guard = new ScopeGuard(makeToken());
      expect(() => guard.checkAccess("use", "any-project")).not.toThrow();
    });
  });

  describe("secret name scoping", () => {
    it("allows access to named secrets", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key", "db-pass"] }));
      expect(() => guard.checkAccess("use", undefined, "api-key")).not.toThrow();
    });

    it("denies access to unnamed secrets", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key"] }));
      expect(() => guard.checkAccess("use", undefined, "other-secret")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("allows when no secret name in context", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key"] }));
      expect(() => guard.checkAccess("list")).not.toThrow();
    });

    it("allows when token has no secrets scope", () => {
      const guard = new ScopeGuard(makeToken());
      expect(() => guard.checkAccess("use", undefined, "any-secret")).not.toThrow();
    });

    it("matches secret-name patterns with * wildcards (thesis §4.7)", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["db-*"] }));
      expect(() => guard.checkAccess("use", undefined, "db-prod")).not.toThrow();
      expect(() => guard.checkAccess("use", undefined, "db-staging")).not.toThrow();
      expect(() => guard.checkAccess("use", undefined, "api-key")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("mixes literal names and patterns", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key", "db-*"] }));
      expect(() => guard.checkAccess("use", undefined, "api-key")).not.toThrow();
      expect(() => guard.checkAccess("use", undefined, "db-prod")).not.toThrow();
      expect(() => guard.checkAccess("use", undefined, "github-token")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("anchors patterns to the whole name", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["db-*"] }));
      expect(() => guard.checkAccess("use", undefined, "mydb-prod")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });
  });

  describe("filterByScope", () => {
    const secrets = [
      { name: "db-prod", project: "api" },
      { name: "db-staging", project: "api" },
      { name: "api-key", project: "api" },
      { name: "github-token", project: null },
    ];

    it("passes everything through without a token", () => {
      const guard = new ScopeGuard(null);
      expect(guard.filterByScope(secrets)).toEqual(secrets);
    });

    it("filters by secret-name patterns", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["db-*"] }));
      expect(guard.filterByScope(secrets).map((s) => s.name)).toEqual(["db-prod", "db-staging"]);
    });

    it("filters by exact names and patterns together", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key", "db-*"] }));
      expect(guard.filterByScope(secrets).map((s) => s.name)).toEqual([
        "db-prod",
        "db-staging",
        "api-key",
      ]);
    });

    it("combines project and name-pattern filtering", () => {
      const guard = new ScopeGuard(makeToken({ project: "api", secrets: ["db-*"] }));
      expect(guard.filterByScope(secrets).map((s) => s.name)).toEqual(["db-prod", "db-staging"]);
    });
  });

  describe("combined enforcement", () => {
    it("enforces permission + project + secret name", () => {
      const guard = new ScopeGuard(
        makeToken({
          scope: ["use"],
          project: "prod",
          secrets: ["api-key"],
        }),
      );

      // All match
      expect(() => guard.checkAccess("use", "prod", "api-key")).not.toThrow();

      // Wrong permission
      expect(() => guard.checkAccess("create", "prod", "api-key")).toThrow();

      // Wrong project
      expect(() => guard.checkAccess("use", "dev", "api-key")).toThrow();

      // Wrong secret
      expect(() => guard.checkAccess("use", "prod", "other")).toThrow();
    });
  });

  describe("onRefusal (D2g)", () => {
    const build = (overrides: Partial<VaultApiToken>, seen: ReturnType<typeof vi.fn>) =>
      new ScopeGuard(makeToken(overrides), "mcp", undefined, undefined, seen);

    it("reports the permission branch with the operation, once, then throws", () => {
      const seen = vi.fn();
      expect(() =>
        build({ scope: ["list"] }, seen).checkAccess(
          "create",
          undefined,
          undefined,
          "create_secret",
        ),
      ).toThrow(expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }));
      expect(seen).toHaveBeenCalledTimes(1);
      expect(seen).toHaveBeenCalledWith("create_secret", "permission");
    });

    it("reports a cross-project and a global-secret refusal as project", () => {
      const seen = vi.fn();
      const guard = build({ project: "acme" }, seen);
      expect(() => guard.checkAccess("use", "other", "db", "use_secret")).toThrow();
      expect(() => guard.checkAccess("use", undefined, "db", "use_secret")).toThrow();
      expect(seen.mock.calls).toEqual([
        ["use_secret", "project"],
        ["use_secret", "project"],
      ]);
    });

    it("reports the secret-name branch as secret", () => {
      const seen = vi.fn();
      expect(() =>
        build({ secrets: ["db-*"] }, seen).checkAccess("use", undefined, "mail", "use_secret"),
      ).toThrow();
      expect(seen).toHaveBeenCalledWith("use_secret", "secret");
    });

    it("an admitted call, an expired token, a revoked token and a null token report nothing", () => {
      const seen = vi.fn();
      build({}, seen).checkAccess("use", undefined, undefined, "use_secret");
      expect(() =>
        build({ exp: 1 }, seen).checkAccess("use", undefined, undefined, "use_secret"),
      ).toThrow();
      expect(() =>
        new ScopeGuard(makeToken(), "mcp", () => true, undefined, seen).checkAccess(
          "use",
          undefined,
          undefined,
          "use_secret",
        ),
      ).toThrow();
      new ScopeGuard(null, "mcp", undefined, undefined, seen).checkAccess(
        "admin",
        undefined,
        undefined,
        "audit",
      );
      expect(seen).not.toHaveBeenCalled();
    });

    it("a caller naming no operation reports 'unnamed'", () => {
      const seen = vi.fn();
      expect(() => build({ scope: ["list"] }, seen).checkAccess("create")).toThrow();
      expect(seen).toHaveBeenCalledWith("unnamed", "permission");
    });
  });
});

describe("caller (engine-level policy enforcement)", () => {
  it("derives the caller from the token, carrying principal_type through and defaulting the interface to mcp (stdio)", () => {
    const guard = new ScopeGuard(makeToken({ sub: "alice" }));
    expect(guard.caller).toEqual({
      principal_type: "agent",
      principal_id: "alice",
      interface: "mcp",
    });
  });

  it("carries the principal_type claim and project claim through", () => {
    const guard = new ScopeGuard(makeToken({ sub: "ci", principal_type: "tool", project: "api" }));
    expect(guard.caller).toEqual({
      principal_type: "tool",
      principal_id: "ci",
      project: "api",
      interface: "mcp",
    });
  });

  it("stamps mcp-http when constructed for a Streamable HTTP session", () => {
    const guard = new ScopeGuard(makeToken({ sub: "alice" }), "mcp-http");
    expect(guard.caller?.interface).toBe("mcp-http");
  });

  it("without a token is the synthetic tokenless-stdio caller — attribution-only, admin-scoped (R4/E78b)", () => {
    const guard = new ScopeGuard(null);
    expect(guard.caller).toEqual({
      principal_type: "user",
      principal_id: "tokenless-stdio",
      interface: "mcp",
      admin_scope: true,
    });
  });

  it("carries the socket peer into the caller, only when given (E75i)", () => {
    const token = makeToken({ sub: "alice" });
    const withPeer = new ScopeGuard(token, "mcp-http", undefined, "127.0.0.1");
    expect(withPeer.caller.remote_address).toBe("127.0.0.1");
    expect("remote_address" in new ScopeGuard(token).caller).toBe(false);
  });

  it("the interface tag never affects scope enforcement", () => {
    const stdio = new ScopeGuard(makeToken({ scope: ["use"] }), "mcp");
    const http = new ScopeGuard(makeToken({ scope: ["use"] }), "mcp-http");
    expect(() => stdio.checkAccess("use")).not.toThrow();
    expect(() => http.checkAccess("use")).not.toThrow();
    expect(() => stdio.checkAccess("create")).toThrow();
    expect(() => http.checkAccess("create")).toThrow();
  });
});

// H7 + T5: the stdio transport verifies its launch token once, at construction.
// Both mid-session rechecks — expiry and revocation — therefore live here, and
// each must be able to stop a call on a running server.
describe("ScopeGuard mid-session token rechecks", () => {
  it("refuses an expired token even when the permission is granted", () => {
    const guard = new ScopeGuard(makeToken({ exp: Math.floor(Date.now() / 1000) - 1 }));
    expect(() => guard.checkAccess("use")).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_EXPIRED }),
    );
  });

  it("checks expiry before the permission — an expired admin token does not pass", () => {
    const guard = new ScopeGuard(
      makeToken({ scope: ["admin"], exp: Math.floor(Date.now() / 1000) - 1 }),
    );
    expect(() => guard.checkAccess("create")).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_EXPIRED }),
    );
  });

  it("refuses a revoked token", () => {
    const guard = new ScopeGuard(makeToken(), "mcp", (jti) => jti === "jti-123");
    expect(() => guard.checkAccess("use")).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_REVOKED }),
    );
  });

  it("checks revocation before the permission — a revoked admin token does not pass", () => {
    const guard = new ScopeGuard(makeToken({ scope: ["admin"] }), "mcp", () => true);
    expect(() => guard.checkAccess("create")).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_REVOKED }),
    );
  });

  it("consults the store on every call, not once", () => {
    let revoked = false;
    const guard = new ScopeGuard(makeToken(), "mcp", () => revoked);
    expect(() => guard.checkAccess("use")).not.toThrow();
    revoked = true;
    expect(() => guard.checkAccess("use")).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_REVOKED }),
    );
  });

  it("negative control: an unrevoked token passes", () => {
    const guard = new ScopeGuard(makeToken(), "mcp", (jti) => jti === "some-other-jti");
    expect(() => guard.checkAccess("use")).not.toThrow();
  });

  it("negative control: the tokenless local path is unaffected", () => {
    const guard = new ScopeGuard(null, "mcp", () => true);
    expect(() => guard.checkAccess("admin")).not.toThrow();
  });
});
