import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine, mockResolveSecretValue, mockPromptConfirm } = vi.hoisted(() => ({
  mockEngine: {
    createSecret: vi.fn(),
    rotateSecret: vi.fn(),
    revokeSecret: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockResolveSecretValue: vi.fn(),
  mockPromptConfirm: vi.fn(),
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));
vi.mock("../../utils/secret-value.js", () => ({ resolveSecretValue: mockResolveSecretValue }));
vi.mock("../../utils/prompt.js", () => ({ promptConfirm: mockPromptConfirm }));

import { registerSecretSetCommand } from "./set.js";
import { registerSecretRotateCommand } from "./rotate.js";
import { registerSecretDeleteCommand } from "./delete.js";

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

describe("secret set/rotate/delete — token path", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockResolveSecretValue.mockResolvedValue(new TextEncoder().encode("v"));
    mockPromptConfirm.mockResolvedValue(true);
    mockEngine.createSecret.mockResolvedValue({ handle: "secret://k" });
    mockEngine.rotateSecret.mockResolvedValue(undefined);
    mockEngine.revokeSecret.mockResolvedValue(undefined);
    mockEngine.verifyToken.mockReturnValue(token());
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    // Same rationale as get.token.test.ts / list.token.test.ts: a blanket
    // vi.restoreAllMocks() here also tears down the vi.mock'd
    // loadUnlockedEngine (a bare vi.fn(), not a spy on a real function), so
    // restore only the spies actually created here.
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
    registerSecretSetCommand(secret);
    registerSecretRotateCommand(secret);
    registerSecretDeleteCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", ...args]);
  }

  it("set: create-scoped token passes the caller with project+name dims", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["create"], project: "api" }));
    await run(["set", "db-key", "--project", "api", "--token", "jwt-value"]);
    expect(mockEngine.createSecret).toHaveBeenCalledWith(
      expect.objectContaining({ name: "db-key", project: "api" }),
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });

  it("set: scope refusal happens before the value is collected", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["use"] }));
    await expect(run(["set", "db-key", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(mockResolveSecretValue).not.toHaveBeenCalled();
    expect(mockEngine.createSecret).not.toHaveBeenCalled();
  });

  it("rotate: rotate-scoped token passes the caller; refusal precedes value collection", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["rotate", "secret://db-key", "--token", "jwt-value"]);
    expect(mockEngine.rotateSecret).toHaveBeenCalledWith(
      "secret://db-key",
      expect.any(Uint8Array),
      expect.objectContaining({ interface: "cli" }),
    );

    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    mockResolveSecretValue.mockClear();
    await expect(run(["rotate", "secret://db-key", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(mockResolveSecretValue).not.toHaveBeenCalled();
  });

  it("delete: revoke-scoped token passes the caller; refusal precedes the prompt", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["revoke"] }));
    await run(["delete", "secret://db-key", "--confirm", "--token", "jwt-value"]);
    expect(mockEngine.revokeSecret).toHaveBeenCalledWith(
      "secret://db-key",
      expect.objectContaining({ interface: "cli" }),
    );

    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(run(["delete", "secret://db-key", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(mockPromptConfirm).not.toHaveBeenCalled();
  });

  it("delete: a declined prompt aborts cleanly and destroys the engine", async () => {
    mockPromptConfirm.mockResolvedValue(false);
    await run(["delete", "secret://db-key"]);
    expect(mockEngine.revokeSecret).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalled();
  });

  it("delete/set/rotate: tokenless paths pass no caller", async () => {
    await run(["set", "k"]);
    expect(mockEngine.createSecret).toHaveBeenCalledWith(expect.anything(), undefined);
    await run(["rotate", "secret://k"]);
    expect(mockEngine.rotateSecret).toHaveBeenCalledWith(
      "secret://k",
      expect.anything(),
      undefined,
    );
    await run(["delete", "secret://k", "--confirm"]);
    expect(mockEngine.revokeSecret).toHaveBeenCalledWith("secret://k", undefined);
  });
});
