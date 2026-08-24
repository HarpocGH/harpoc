import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getConnectionConfig: vi.fn(),
    setConnectionConfig: vi.fn(),
    deleteConnectionConfig: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretConnectionCommand } from "./connection.js";

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

describe("secret connection — token path", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.getConnectionConfig.mockResolvedValue({
      database: { tls_mode: "require" },
    });
    mockEngine.setConnectionConfig.mockResolvedValue(undefined);
    mockEngine.deleteConnectionConfig.mockResolvedValue(true);
    mockEngine.verifyToken.mockReturnValue(token());
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

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>");
    const secret = program.command("secret");
    registerSecretConnectionCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "connection", ...args]);
  }

  it("--delete requires rotate and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--delete", "--token", "jwt-value"]);
    expect(mockEngine.deleteConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("show requires read and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await run(["secret://k", "--show", "--token", "jwt-value"]);
    expect(mockEngine.getConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set requires rotate — a read-scoped token is refused before any engine call", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(
      run(["secret://k", "--db-tls", "require", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.setConnectionConfig).not.toHaveBeenCalled();
  });

  it("set mode's merge read is caller-less", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--db-tls", "require", "--token", "jwt-value"]);
    expect(mockEngine.getConnectionConfig).toHaveBeenCalledWith("secret://k");
    expect(mockEngine.setConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ database: expect.objectContaining({ tls_mode: "require" }) }),
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set passes the caller; tokenless set passes none", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--db-tls", "require", "--token", "jwt-value"]);
    expect(mockEngine.setConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ database: expect.objectContaining({ tls_mode: "require" }) }),
      expect.objectContaining({ interface: "cli" }),
    );
    await run(["secret://k", "--db-tls", "require"]);
    expect(mockEngine.setConnectionConfig).toHaveBeenLastCalledWith(
      "secret://k",
      expect.anything(),
      undefined,
    );
  });
});
