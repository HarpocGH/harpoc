import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getMcpServerConfig: vi.fn(),
    setMcpServerConfig: vi.fn().mockResolvedValue(undefined),
    deleteMcpServerConfig: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretMcpServerCommand } from "./mcp-server.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerSecretMcpServerCommand(program.command("secret")),
  ["secret", "mcp-server"],
);

// I25 (test-review-2026-10-09): getting-started documents `secret mcp-server
// --transport stdio --command … --arg … --env-var …` (the CLI also has --cwd);
// every other suite configures the http transport only.
describe("secret mcp-server — the stdio transport flags (I25)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("--transport stdio with --command, repeated --arg, --env-var and --cwd lands in setMcpServerConfig", async () => {
    await run([
      "secret://k",
      "--name",
      "local-mcp",
      "--transport",
      "stdio",
      "--command",
      "/usr/bin/node",
      "--arg",
      "server.js",
      "--arg",
      "stdio",
      "--env-var",
      "MCP_TOKEN",
      "--cwd",
      "/srv/mcp",
    ]);
    expect(mockEngine.setMcpServerConfig).toHaveBeenCalledTimes(1);
    expect(mockEngine.setMcpServerConfig).toHaveBeenCalledWith(
      "secret://k",
      {
        server_name: "local-mcp",
        transport: "stdio",
        protocol: "2025-11-25",
        command: "/usr/bin/node",
        args: ["server.js", "stdio"],
        env_var: "MCP_TOKEN",
        working_directory: "/srv/mcp",
      },
      undefined,
    );
    expect(spies.stderr()).toBe("OK: MCP server config updated (secret://k)");
  });
});
