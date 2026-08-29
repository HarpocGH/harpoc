import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getSecretInfo: vi.fn(),
    getSecretValue: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretGetCommand } from "./get.js";

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["read"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    principal_type: "agent",
    ...overrides,
  };
}

const INFO = {
  handle: "secret://api-key",
  name: "api-key",
  type: "api_key",
  project: null,
  status: "active",
  version: 1,
  createdAt: 0,
  updatedAt: 0,
  expiresAt: null,
  rotatedAt: null,
};

describe("secret get — token path", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let stdoutWriteSpy: MockInstance;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.getSecretInfo.mockResolvedValue(INFO);
    mockEngine.getSecretValue.mockResolvedValue(new TextEncoder().encode("v"));
    mockEngine.verifyToken.mockReturnValue(token());
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    stdoutWriteSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    // A blanket vi.restoreAllMocks() here also tears down the vi.mock'd
    // loadUnlockedEngine (a bare vi.fn(), not a spy on a real function) —
    // mockRestore() on it resets it to a no-op, so every test after the
    // first in this file saw `engine` come back undefined. Restoring only
    // the spies actually created here, as use.test.ts already does, avoids
    // that collateral damage.
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    stdoutWriteSpy.mockRestore();
    if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
    else process.env.HARPOC_TOKEN = savedEnvToken;
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>");
    const secret = program.command("secret");
    registerSecretGetCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "get", ...args]);
  }

  it("tokenless path is unchanged: no verify, no caller", async () => {
    await run(["secret://api-key"]);
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.getSecretInfo).toHaveBeenCalledWith("secret://api-key", undefined);
  });

  it("info read passes the cli caller under read scope", async () => {
    await run(["secret://api-key", "--token", "jwt-value"]);
    expect(mockEngine.getSecretInfo).toHaveBeenCalledWith("secret://api-key", {
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
  });

  it("--value passes the cli caller under read scope (design decision 3)", async () => {
    await run(["secret://api-key", "--value", "--token", "jwt-value"]);
    expect(mockEngine.getSecretValue).toHaveBeenCalledWith("secret://api-key", {
      principal_type: "agent",
      principal_id: "agent-1",
      interface: "cli",
    });
  });

  it("a use-scoped token is refused before any engine read", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["use"] }));
    await expect(run(["secret://api-key", "--value", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(mockEngine.getSecretValue).not.toHaveBeenCalled();
    expect(mockEngine.getSecretInfo).not.toHaveBeenCalled();
  });

  it("reads an ambient HARPOC_TOKEN and refuses an empty one", async () => {
    process.env.HARPOC_TOKEN = "env-jwt";
    await run(["secret://api-key"]);
    expect(mockEngine.verifyToken).toHaveBeenCalledWith("env-jwt");

    process.env.HARPOC_TOKEN = "";
    await expect(run(["secret://api-key"])).rejects.toThrow("process.exit");
  });
});
