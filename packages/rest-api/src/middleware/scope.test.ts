import { describe, expect, it, vi } from "vitest";
import { VaultState } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { createApp } from "../app.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const USE_ONLY_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["use"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

const HEADERS = { host: "localhost", authorization: "Bearer valid-jwt" };
const TOKEN_PARTS = ["eyJhbGciOiJFZERTQSJ9", "eyJzdWIiOiJ1c2UtYWdlbnQifQ", "c2ln-bmF0_dXJl"];
const PASTED_TOKEN = TOKEN_PARTS.join(".");
const MINTED_JTI = "019a7c3e-5b2d-7f10-8a4b-3c2d1e0f9a8b";
const REPEATED_EYJ = "eyJ".repeat(5334).slice(0, 16_000);

function createMockEngine() {
  return {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    verifyToken: vi.fn().mockReturnValue(USE_ONLY_TOKEN),
    auditGovernanceRefusal: vi.fn(),
    auditScopeRefusal: vi.fn(),
    revokeToken: vi.fn(),
    getSecretInfo: vi.fn(),
  };
}

describe("recordScopeRefusal records a token-shaped path segment as <token> (C-10)", () => {
  it("a use-only token's DELETE /api/v1/tokens/<a whole token> hands auditScopeRefusal DELETE /api/v1/tokens/<token>", async () => {
    const engine = createMockEngine();
    const res = await createApp(engine as never).request(`/api/v1/tokens/${PASTED_TOKEN}`, {
      method: "DELETE",
      headers: HEADERS,
    });

    expect(res.status).toBe(403);
    expect(engine.revokeToken).toHaveBeenCalledTimes(0);
    expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
    const [, operation, reason] = engine.auditScopeRefusal.mock.calls[0] as [
      unknown,
      string,
      string,
    ];
    expect(operation === "DELETE /api/v1/tokens/<token>").toBe(true);
    expect(reason).toBe("permission");
    expect(JSON.stringify(engine.auditScopeRefusal.mock.calls).includes(PASTED_TOKEN)).toBe(false);
  });

  it.each([
    ["followed by %0A", `${PASTED_TOKEN}%0A`],
    ["between %22 and %22", `%22${PASTED_TOKEN}%22`],
    ["after Bearer%20", `Bearer%20${PASTED_TOKEN}`],
  ])(
    "a segment holding a whole token %s is recorded as <token>, whole",
    async (_label, segment) => {
      const engine = createMockEngine();
      const res = await createApp(engine as never).request(`/api/v1/tokens/${segment}`, {
        method: "DELETE",
        headers: HEADERS,
      });

      expect(res.status).toBe(403);
      expect(engine.revokeToken).toHaveBeenCalledTimes(0);
      expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
      const operation = engine.auditScopeRefusal.mock.calls[0]?.[1] as string;
      expect(operation === "DELETE /api/v1/tokens/<token>").toBe(true);
      expect(JSON.stringify(engine.auditScopeRefusal.mock.calls).includes(PASTED_TOKEN)).toBe(
        false,
      );
    },
  );

  it("control characters left in a segment are recorded as their percent-escapes", async () => {
    const engine = createMockEngine();
    const res = await createApp(engine as never).request("/api/v1/tokens/x%0D%0Ay%1Bz", {
      method: "DELETE",
      headers: HEADERS,
    });

    expect(res.status).toBe(403);
    expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
    const operation = engine.auditScopeRefusal.mock.calls[0]?.[1] as string;
    expect(/[\p{Cc}\u2028\u2029]/u.test(operation)).toBe(false);
    expect(operation).toBe("DELETE /api/v1/tokens/x%0D%0Ay%1Bz");
  });

  it.each([
    ["its first part", `eyJhbGciOiJF%0AZERTQSJ9.${TOKEN_PARTS[1]}.${TOKEN_PARTS[2]}`],
    ["its second part", `${TOKEN_PARTS[0]}.eyJzdWIiOiJ1c2Ut%0AYWdlbnQifQ.${TOKEN_PARTS[2]}`],
  ])("a token with %0A inside %s is recorded as <token>, whole", async (_label, segment) => {
    const engine = createMockEngine();
    const res = await createApp(engine as never).request(`/api/v1/tokens/${segment}`, {
      method: "DELETE",
      headers: HEADERS,
    });

    expect(res.status).toBe(403);
    expect(engine.revokeToken).toHaveBeenCalledTimes(0);
    expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
    const operation = engine.auditScopeRefusal.mock.calls[0]?.[1] as string;
    expect(operation === "DELETE /api/v1/tokens/<token>").toBe(true);
    const recorded = JSON.stringify(engine.auditScopeRefusal.mock.calls);
    expect(TOKEN_PARTS.some((part) => recorded.includes(part))).toBe(false);
  });

  it("DEL, a C1 control, U+2028 and U+2029 are recorded as their percent-escapes", async () => {
    const path = "/api/v1/tokens/x%7Fy%C2%85z%E2%80%A8%E2%80%A9";
    const engine = createMockEngine();
    const res = await createApp(engine as never).request(path, {
      method: "DELETE",
      headers: HEADERS,
    });

    expect(res.status).toBe(403);
    expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
    const operation = engine.auditScopeRefusal.mock.calls[0]?.[1] as string;
    expect(/[\p{Cc}\u2028\u2029]/u.test(operation)).toBe(false);
    expect(operation === `DELETE ${path}`).toBe(true);
  });

  it.each([
    ["a minted jti", "DELETE", `/api/v1/tokens/${MINTED_JTI}`, `/api/v1/tokens/${MINTED_JTI}`],
    ["a handle", "GET", "/api/v1/secrets/db-main", "/api/v1/secrets/db-main"],
    ["a percent-encoded name", "GET", "/api/v1/secrets/db%2Dmain", "/api/v1/secrets/db-main"],
    ["a handle that begins eyJ", "GET", "/api/v1/secrets/eyJ-main", "/api/v1/secrets/eyJ-main"],
    ["a two-part eyJa.b segment", "DELETE", "/api/v1/tokens/eyJa.b", "/api/v1/tokens/eyJa.b"],
    [
      "a segment of 16 000 characters of repeated eyJ without a dot",
      "DELETE",
      `/api/v1/tokens/${REPEATED_EYJ}`,
      `/api/v1/tokens/${REPEATED_EYJ}`,
    ],
  ])("control: %s is recorded as before", async (_label, method, path, recorded) => {
    const engine = createMockEngine();
    const res = await createApp(engine as never).request(path, { method, headers: HEADERS });

    expect(res.status).toBe(403);
    expect(engine.revokeToken).not.toHaveBeenCalled();
    expect(engine.getSecretInfo).not.toHaveBeenCalled();
    expect(engine.auditScopeRefusal).toHaveBeenCalledTimes(1);
    expect(engine.auditScopeRefusal).toHaveBeenCalledWith(
      expect.anything(),
      `${method} ${recorded}`,
      "permission",
    );
  });
});
