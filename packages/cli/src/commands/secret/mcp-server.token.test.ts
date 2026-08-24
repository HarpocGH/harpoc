import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getMcpServerConfig: vi.fn(),
    setMcpServerConfig: vi.fn(),
    deleteMcpServerConfig: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretMcpServerCommand } from "./mcp-server.js";

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

describe("secret mcp-server — token path", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.getMcpServerConfig.mockResolvedValue({
      server_name: "srv",
      transport: "http",
      url: "https://mcp.example.com/mcp",
    });
    mockEngine.setMcpServerConfig.mockResolvedValue(undefined);
    mockEngine.deleteMcpServerConfig.mockResolvedValue(true);
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
    registerSecretMcpServerCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "mcp-server", ...args]);
  }

  it("--delete requires rotate and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--delete", "--token", "jwt-value"]);
    expect(mockEngine.deleteMcpServerConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("show requires read and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await run(["secret://k", "--show", "--token", "jwt-value"]);
    expect(mockEngine.getMcpServerConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set requires rotate — a read-scoped token is refused before any engine call", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(
      run([
        "secret://k",
        "--name",
        "srv",
        "--transport",
        "http",
        "--url",
        "https://mcp.example.com/mcp",
        "--token",
        "jwt-value",
      ]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.setMcpServerConfig).not.toHaveBeenCalled();
  });

  it("set passes the caller; tokenless set passes none", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run([
      "secret://k",
      "--name",
      "srv",
      "--transport",
      "http",
      "--url",
      "https://mcp.example.com/mcp",
      "--token",
      "jwt-value",
    ]);
    expect(mockEngine.setMcpServerConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ server_name: "srv" }),
      expect.objectContaining({ interface: "cli" }),
    );
    await run([
      "secret://k",
      "--name",
      "srv",
      "--transport",
      "http",
      "--url",
      "https://mcp.example.com/mcp",
    ]);
    expect(mockEngine.setMcpServerConfig).toHaveBeenLastCalledWith(
      "secret://k",
      expect.anything(),
      undefined,
    );
  });
});
