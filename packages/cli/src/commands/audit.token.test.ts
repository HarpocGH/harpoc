import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { VaultApiToken } from "@harpoc/shared";

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
      .mockReturnValue({ valid: true, firstBrokenId: null, checked: 0, legacy: 0, tail: null }),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { Command } from "commander";
import { registerAuditCommand } from "./audit.js";

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    ...overrides,
  };
}

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  registerAuditCommand(program);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", ...args]);
}

describe("audit — token path", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
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
      legacy: 0,
      tail: null,
    });
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
    else process.env.HARPOC_TOKEN = savedEnvToken;
  });

  it("listing under an admin token passes the visibility scope", async () => {
    mockEngine.verifyToken.mockReturnValue(
      token({ scope: ["admin"], project: "api", secrets: ["db-*"] }),
    );
    await run(["audit", "--token", "jwt-value"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(expect.anything(), {
      project: "api",
      secrets: ["db-*"],
    });
  });

  it("an unrestricted admin token passes no visibility scope", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["admin"] }));
    await run(["audit", "--token", "jwt-value"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(expect.anything(), undefined);
  });

  it("a non-admin token is refused before the query", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(run(["audit", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(mockEngine.queryAudit).not.toHaveBeenCalled();
  });

  it("verify and anchor are admin-gated under a token", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(run(["audit", "verify", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
    await expect(run(["audit", "anchor", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(mockEngine.getAuditChainTail).not.toHaveBeenCalled();

    mockEngine.verifyToken.mockReturnValue(token({ scope: ["admin"] }));
    await run(["audit", "verify", "--token", "jwt-value"]);
    expect(mockEngine.verifyAuditChain).toHaveBeenCalled();
  });

  it("tokenless audit is unchanged", async () => {
    await run(["audit"]);
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(expect.anything(), undefined);
  });
});
