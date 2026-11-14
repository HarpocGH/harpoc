import { describe, expect, it, vi } from "vitest";
import { VaultState } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { createApp } from "../app.js";
import { silenceAuditLines } from "@harpoc/test-utils";

silenceAuditLines();

const CLAIMED_TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["admin"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
  project: "acme",
};

const HEADERS = { host: "localhost", authorization: "Bearer valid-jwt" };
const PASTED_TOKEN = ["eyJhbGciOiJFZERTQSJ9", "eyJzdWIiOiJnb3YtYWRtaW4ifQ", "c2ln-bmF0_dXJl"].join(
  ".",
);
const MINTED_JTI = "019a7c3e-5b2d-7f10-8a4b-3c2d1e0f9a8b";

function createMockEngine() {
  return {
    getState: vi.fn().mockReturnValue(VaultState.UNLOCKED),
    verifyToken: vi.fn().mockReturnValue(CLAIMED_TOKEN),
    auditGovernanceRefusal: vi.fn(),
    auditScopeRefusal: vi.fn(),
    revokeToken: vi.fn(),
  };
}

describe("unscopedTokenMiddleware records a token-shaped path segment as <token> (C-10)", () => {
  it("a claimed token's DELETE /api/v1/tokens/<a whole token> hands auditGovernanceRefusal DELETE /api/v1/tokens/<token>", async () => {
    const engine = createMockEngine();
    const res = await createApp(engine as never).request(`/api/v1/tokens/${PASTED_TOKEN}`, {
      method: "DELETE",
      headers: HEADERS,
    });

    expect(res.status).toBe(403);
    expect(engine.revokeToken).toHaveBeenCalledTimes(0);
    expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
    const operation = engine.auditGovernanceRefusal.mock.calls[0]?.[1] as string;
    expect(operation === "DELETE /api/v1/tokens/<token>").toBe(true);
    expect(JSON.stringify(engine.auditGovernanceRefusal.mock.calls).includes(PASTED_TOKEN)).toBe(
      false,
    );
  });

  it("a segment holding a whole token after Bearer%20 is recorded as <token>, whole", async () => {
    const engine = createMockEngine();
    const res = await createApp(engine as never).request(
      `/api/v1/tokens/Bearer%20${PASTED_TOKEN}`,
      {
        method: "DELETE",
        headers: HEADERS,
      },
    );

    expect(res.status).toBe(403);
    expect(engine.revokeToken).toHaveBeenCalledTimes(0);
    expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
    const operation = engine.auditGovernanceRefusal.mock.calls[0]?.[1] as string;
    expect(operation === "DELETE /api/v1/tokens/<token>").toBe(true);
    expect(JSON.stringify(engine.auditGovernanceRefusal.mock.calls).includes(PASTED_TOKEN)).toBe(
      false,
    );
  });

  it("control: a minted jti is recorded as before", async () => {
    const engine = createMockEngine();
    const res = await createApp(engine as never).request(`/api/v1/tokens/${MINTED_JTI}`, {
      method: "DELETE",
      headers: HEADERS,
    });

    expect(res.status).toBe(403);
    expect(engine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
    expect(engine.auditGovernanceRefusal.mock.calls[0]?.[1]).toBe(
      `DELETE /api/v1/tokens/${MINTED_JTI}`,
    );
  });
});
