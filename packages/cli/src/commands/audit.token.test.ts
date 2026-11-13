import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    queryAudit: vi.fn().mockReturnValue([]),
    getAuditChainTail: vi.fn().mockReturnValue({
      format: "harpoc-audit-anchor/1",
      last_id: 1,
      row_hmac: "aa",
      timestamp: 0,
    }),
    verifyAuditChain: vi
      .fn()
      .mockReturnValue({ valid: true, firstBrokenId: null, checked: 0, tail: null }),
    verifyToken: vi.fn(),
    auditScopeRefusal: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerAuditCommand } from "./audit.js";
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../__fixtures__/cli-harness.js";

const run = buildCli(registerAuditCommand);

const CLI_CALLER = {
  principal_type: "agent",
  principal_id: "agent-1",
  interface: "cli",
  admin_scope: true,
};

describe("audit — token path", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.queryAudit.mockReturnValue([]);
    mockEngine.getAuditChainTail.mockReturnValue({
      format: "harpoc-audit-anchor/1",
      last_id: 1,
      row_hmac: "aa",
      timestamp: 0,
    });
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: true,
      firstBrokenId: null,
      checked: 0,
      tail: null,
    });
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("listing under an admin token passes the visibility scope", async () => {
    mockEngine.verifyToken.mockReturnValue(
      tokenFixture({ scope: ["admin"], project: "api", secrets: ["db-*"] }),
    );
    await run(["audit", "--token", "jwt-value"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(
      expect.anything(),
      { project: "api", secrets: ["db-*"] },
      { ...CLI_CALLER, project: "api", secrets: ["db-*"] },
    );
  });

  it("an unrestricted admin token passes no visibility scope", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await run(["audit", "--token", "jwt-value"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(expect.anything(), undefined, CLI_CALLER);
  });

  it("a non-admin token is refused before the query", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await expect(run(["audit", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenLastCalledWith(
      expect.stringContaining("[ACCESS_DENIED] Access denied: Token lacks permission: admin"),
    );
    expect(mockEngine.queryAudit).not.toHaveBeenCalled();
  });

  it("verify and anchor are admin-gated under a token", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await expect(run(["audit", "verify", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenLastCalledWith(
      expect.stringContaining("[ACCESS_DENIED] Access denied: Token lacks permission: admin"),
    );
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
    await expect(run(["audit", "anchor", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenLastCalledWith(
      expect.stringContaining("[ACCESS_DENIED] Access denied: Token lacks permission: admin"),
    );
    expect(mockEngine.getAuditChainTail).not.toHaveBeenCalled();

    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await run(["audit", "verify", "--token", "jwt-value"]);
    expect(mockEngine.verifyAuditChain).toHaveBeenCalled();
  });

  it("verify and anchor under an admin token pass the token's caller", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await run(["audit", "verify", "--token", "jwt-value"]);
    await run(["audit", "anchor", "--token", "jwt-value"]);
    expect(mockEngine.verifyAuditChain.mock.calls).toEqual([[undefined, CLI_CALLER]]);
    expect(mockEngine.getAuditChainTail.mock.calls).toEqual([[CLI_CALLER]]);
  });

  it("tokenless audit is unchanged", async () => {
    await run(["audit"]);
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(expect.anything(), undefined, undefined);
  });
});
