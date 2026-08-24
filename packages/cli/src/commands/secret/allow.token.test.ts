import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getInjectionPolicy: vi.fn(),
    setInjectionPolicy: vi.fn().mockResolvedValue(undefined),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretAllowCommand } from "./allow.js";

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

describe("secret allow — token path", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.getInjectionPolicy.mockResolvedValue({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
    });
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
    registerSecretAllowCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "allow", ...args]);
  }

  it("show mode checks read scope and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await run(["secret://k", "--show", "--token", "jwt-value"]);
    expect(mockEngine.getInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set mode checks rotate scope; the merge read is caller-less; the caller reaches setInjectionPolicy", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--url", "https://api.example.com/*", "--token", "jwt-value"]);
    expect(mockEngine.getInjectionPolicy).toHaveBeenCalledWith("secret://k");
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ url_allowlist: ["https://api.example.com/*"] }),
      { acknowledge_interpreters: false },
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });

  it("a read-scoped token cannot set; refusal precedes the merge read", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(
      run(["secret://k", "--url", "https://api.example.com/*", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.getInjectionPolicy).not.toHaveBeenCalled();
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  it("tokenless set path is unchanged (three-argument call)", async () => {
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.anything(),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  // v1.3: --recipient / --imap-read-only ride the existing rotate scope —
  // no new token-parity entry (token-parity.test.ts is unchanged by this task).
  it("--imap-read-only rides the existing rotate scope", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--imap-read-only", "--token", "jwt-value"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ imap_read_only: true }),
      { acknowledge_interpreters: false },
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });
});
