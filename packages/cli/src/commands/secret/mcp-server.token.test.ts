import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

describe("secret mcp-server — token path", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEngine.getMcpServerConfig.mockResolvedValue({
      server_name: "srv",
      transport: "http",
      url: "https://mcp.example.com/mcp",
    });
    mockEngine.setMcpServerConfig.mockResolvedValue(undefined);
    mockEngine.deleteMcpServerConfig.mockResolvedValue(true);
    mockEngine.verifyToken.mockReturnValue(tokenFixture());
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  const run = buildCli(
    (program) => registerSecretMcpServerCommand(program.command("secret")),
    ["secret", "mcp-server"],
  );

  it("--delete requires rotate and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
    await run(["secret://k", "--delete", "--token", "jwt-value"]);
    expect(mockEngine.deleteMcpServerConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("show requires read and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await run(["secret://k", "--show", "--token", "jwt-value"]);
    expect(mockEngine.getMcpServerConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set requires rotate — a read-scoped token is refused before any engine call", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
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
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
    expect(mockEngine.setMcpServerConfig).not.toHaveBeenCalled();
  });

  it("set passes the caller; tokenless set passes none", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
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

  it("--protocol 2026-07-28 reaches setMcpServerConfig with the modern revision", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
    await run([
      "secret://k",
      "--name",
      "srv",
      "--transport",
      "http",
      "--url",
      "https://mcp.example.com/mcp",
      "--protocol",
      "2026-07-28",
      "--token",
      "jwt-value",
    ]);
    expect(mockEngine.setMcpServerConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ protocol: "2026-07-28" }),
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("omitting --protocol defaults to 2025-11-25", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
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
      expect.objectContaining({ protocol: "2025-11-25" }),
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("--protocol 2025-03-26 is refused with the renderer's enum wording, value-free", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
    await expect(
      run([
        "secret://k",
        "--name",
        "srv",
        "--transport",
        "http",
        "--url",
        "https://mcp.example.com/mcp",
        "--protocol",
        "2025-03-26",
        "--token",
        "jwt-value",
      ]),
    ).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("protocol: must be one of 2025-11-25, 2026-07-28"),
    );
    expect(spies.errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("2025-03-26"));
    expect(mockEngine.setMcpServerConfig).not.toHaveBeenCalled();
  });
});
