import { describe, expect, it } from "vitest";
import { callerFromToken } from "./caller.js";
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
    for (const iface of ["rest", "mcp", "mcp-http"] as const) {
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
