import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    revokeToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { Command } from "commander";
import { VaultError } from "@harpoc/shared";
import { registerAuthRevokeCommand } from "./revoke.js";

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const auth = program.command("auth");
  registerAuthRevokeCommand(auth);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "auth", "revoke", ...args]);
}

describe("auth revoke (registry-authoritative, R9/C33-A)", () => {
  const savedEnv = process.env.HARPOC_TOKEN;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: MockInstance;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.HARPOC_TOKEN;
    } else {
      process.env.HARPOC_TOKEN = savedEnv;
    }
    logSpy.mockRestore();
    errSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("revokes by jti alone — no expiry, no token", async () => {
    await run(["some-jti"]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti");
    expect(mockEngine.revokeToken.mock.calls[0]).toHaveLength(1);
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("ignores an ambient HARPOC_TOKEN entirely — the registry knows the expiry", async () => {
    process.env.HARPOC_TOKEN = "header.payload.signature";
    await run(["some-jti"]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti");
    const warned = errSpy.mock.calls.some(
      (call) => typeof call[0] === "string" && call[0].startsWith("Warning:"),
    );
    expect(warned).toBe(false);
  });

  it("--token is an unknown option", async () => {
    await expect(run(["some-jti", "--token", "header.payload.signature"])).rejects.toThrow();
    expect(mockEngine.revokeToken).not.toHaveBeenCalled();
  });

  it("surfaces the engine's refusal of an unknown jti", async () => {
    mockEngine.revokeToken.mockImplementationOnce(() => {
      throw VaultError.invalidInput("Unknown token jti: nope");
    });
    await expect(run(["nope"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining("Unknown token jti: nope"));
    expect(mockEngine.destroy).toHaveBeenCalled();
  });
});
