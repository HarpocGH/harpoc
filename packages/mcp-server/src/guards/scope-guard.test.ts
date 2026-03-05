import { describe, it, expect } from "vitest";
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
    ...overrides,
  };
}

describe("ScopeGuard", () => {
  describe("null token (full access)", () => {
    it("allows any permission", () => {
      const guard = new ScopeGuard(null);
      expect(guard.checkAccess("use")).toBe("local");
      expect(guard.checkAccess("create")).toBe("local");
      expect(guard.checkAccess("admin")).toBe("local");
    });

    it("returns 'local' as principal", () => {
      const guard = new ScopeGuard(null);
      expect(guard.principal).toBe("local");
    });
  });

  describe("permission enforcement", () => {
    it("allows permitted actions", () => {
      const guard = new ScopeGuard(makeToken({ scope: ["use", "list"] }));
      expect(guard.checkAccess("use")).toBe("test-agent");
      expect(guard.checkAccess("list")).toBe("test-agent");
    });

    it("denies unpermitted actions", () => {
      const guard = new ScopeGuard(makeToken({ scope: ["use", "list"] }));
      expect(() => guard.checkAccess("create")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("admin implies all permissions", () => {
      const guard = new ScopeGuard(makeToken({ scope: ["admin"] }));
      expect(guard.checkAccess("use")).toBe("test-agent");
      expect(guard.checkAccess("create")).toBe("test-agent");
      expect(guard.checkAccess("revoke")).toBe("test-agent");
    });
  });

  describe("project scoping", () => {
    it("allows access to matching project", () => {
      const guard = new ScopeGuard(makeToken({ project: "my-project" }));
      expect(guard.checkAccess("use", "my-project")).toBe("test-agent");
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
      expect(guard.checkAccess("use")).toBe("test-agent");
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
      expect(guard.checkAccess("use", "any-project")).toBe("test-agent");
    });
  });

  describe("secret name scoping", () => {
    it("allows access to named secrets", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key", "db-pass"] }));
      expect(guard.checkAccess("use", undefined, "api-key")).toBe("test-agent");
    });

    it("denies access to unnamed secrets", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key"] }));
      expect(() => guard.checkAccess("use", undefined, "other-secret")).toThrow(
        expect.objectContaining({ code: ErrorCode.ACCESS_DENIED }),
      );
    });

    it("allows when no secret name in context", () => {
      const guard = new ScopeGuard(makeToken({ secrets: ["api-key"] }));
      expect(guard.checkAccess("list")).toBe("test-agent");
    });

    it("allows when token has no secrets scope", () => {
      const guard = new ScopeGuard(makeToken());
      expect(guard.checkAccess("use", undefined, "any-secret")).toBe("test-agent");
    });
  });

  describe("combined enforcement", () => {
    it("enforces permission + project + secret name", () => {
      const guard = new ScopeGuard(makeToken({
        scope: ["use"],
        project: "prod",
        secrets: ["api-key"],
      }));

      // All match
      expect(guard.checkAccess("use", "prod", "api-key")).toBe("test-agent");

      // Wrong permission
      expect(() => guard.checkAccess("create", "prod", "api-key")).toThrow();

      // Wrong project
      expect(() => guard.checkAccess("use", "dev", "api-key")).toThrow();

      // Wrong secret
      expect(() => guard.checkAccess("use", "prod", "other")).toThrow();
    });
  });

  describe("principal", () => {
    it("returns token subject", () => {
      const guard = new ScopeGuard(makeToken({ sub: "my-agent" }));
      expect(guard.principal).toBe("my-agent");
    });
  });
});
