import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

describe("secret set/rotate/delete — token path", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    mockResolveSecretValue.mockResolvedValue(new TextEncoder().encode("v"));
    mockPromptConfirm.mockResolvedValue(true);
    mockEngine.createSecret.mockResolvedValue({ handle: "secret://k" });
    mockEngine.rotateSecret.mockResolvedValue(undefined);
    mockEngine.revokeSecret.mockResolvedValue(undefined);
    mockEngine.verifyToken.mockReturnValue(tokenFixture());
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  const run = buildCli(
    (program) => {
      const secret = program.command("secret");
      registerSecretSetCommand(secret);
      registerSecretRotateCommand(secret);
      registerSecretDeleteCommand(secret);
    },
    ["secret"],
  );

  it("set: create-scoped token passes the caller with project+name dims", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["create"], project: "api" }));
    await run(["set", "db-key", "--project", "api", "--token", "jwt-value"]);
    expect(mockEngine.createSecret).toHaveBeenCalledWith(
      expect.objectContaining({ name: "db-key", project: "api" }),
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });

  it("set: scope refusal happens before the value is collected", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["use"] }));
    await expect(run(["set", "db-key", "--token", "jwt-value"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
    expect(mockResolveSecretValue).not.toHaveBeenCalled();
    expect(mockEngine.createSecret).not.toHaveBeenCalled();
  });

  it("rotate: rotate-scoped token passes the caller; refusal precedes value collection", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
    await run(["rotate", "secret://db-key", "--token", "jwt-value"]);
    expect(mockEngine.rotateSecret).toHaveBeenCalledWith(
      "secret://db-key",
      expect.any(Uint8Array),
      expect.objectContaining({ interface: "cli" }),
    );

    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    mockResolveSecretValue.mockClear();
    await expect(run(["rotate", "secret://db-key", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
    expect(mockResolveSecretValue).not.toHaveBeenCalled();
  });

  it("delete: revoke-scoped token passes the caller; refusal precedes the prompt", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["revoke"] }));
    await run(["delete", "secret://db-key", "--confirm", "--token", "jwt-value"]);
    expect(mockEngine.revokeSecret).toHaveBeenCalledWith(
      "secret://db-key",
      expect.objectContaining({ interface: "cli" }),
    );

    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await expect(run(["delete", "secret://db-key", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
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
