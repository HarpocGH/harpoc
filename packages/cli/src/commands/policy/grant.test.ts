import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    grantPolicy: vi.fn().mockReturnValue({
      id: "policy-1",
      principal_type: "agent",
      principal_id: "agent-1",
      permissions: ["read"],
      expires_at: null,
    }),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
  resolveSecretId: vi.fn().mockResolvedValue("secret-id-1"),
}));

import { Command } from "commander";
import { registerPolicyGrantCommand } from "./grant.js";

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const policy = program.command("policy");
  registerPolicyGrantCommand(policy);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "policy", "grant", ...args]);
}

describe("policy grant --principal-type validation", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
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
  });

  it("rejects an invalid principal type with a clean message before reaching the engine", async () => {
    await expect(
      run([
        "secret://x",
        "--principal-type",
        "banana",
        "--principal-id",
        "a",
        "--permissions",
        "read",
        "--json",
      ]),
    ).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid principal type"));
    expect(mockEngine.grantPolicy).not.toHaveBeenCalled();
  });

  it.each(["agent", "tool", "project", "user"])("accepts principal type %s", async (type) => {
    await run([
      "secret://x",
      "--principal-type",
      type,
      "--principal-id",
      "a",
      "--permissions",
      "read",
      "--json",
    ]);
    expect(mockEngine.grantPolicy).toHaveBeenCalledWith(
      expect.objectContaining({ principalType: type }),
      "cli-user",
    );
  });
});
