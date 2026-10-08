import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../../__fixtures__/cli-harness.js";

describe("secret allow — token path", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
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
    mockEngine.verifyToken.mockReturnValue(tokenFixture());
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  const run = buildCli(
    (program) => registerSecretAllowCommand(program.command("secret")),
    ["secret", "allow"],
  );

  it("show mode checks read scope and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await run(["secret://k", "--show", "--token", "jwt-value"]);
    expect(mockEngine.getInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set mode checks admin scope; the merge read is attributed like the write", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await run(["secret://k", "--url", "https://api.example.com/*", "--token", "jwt-value"]);
    expect(mockEngine.getInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ url_allowlist: ["https://api.example.com/*"] }),
      { acknowledge_interpreters: false },
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });

  it("a read-scoped token cannot set; refusal precedes the merge read", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["read"] }));
    await expect(
      run(["secret://k", "--url", "https://api.example.com/*", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
    expect(mockEngine.getInjectionPolicy).not.toHaveBeenCalled();
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  it("a rotate-scoped token cannot set either — the injection policy is the widening half (R1)", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["rotate"] }));
    await expect(
      run(["secret://k", "--url", "https://api.example.com/*", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(spies.errorSpy).toHaveBeenCalledWith(expect.stringContaining("[ACCESS_DENIED]"));
    expect(mockEngine.getInjectionPolicy).not.toHaveBeenCalled();
    expect(mockEngine.setInjectionPolicy).not.toHaveBeenCalled();
  });

  it("tokenless set path is unchanged (three-argument call)", async () => {
    await run(["secret://k", "--url", "https://api.example.com/*"]);
    expect(mockEngine.getInjectionPolicy).toHaveBeenCalledWith("secret://k", undefined);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.anything(),
      { acknowledge_interpreters: false },
      undefined,
    );
  });

  it("--imap-read-only rides the admin scope like every other write", async () => {
    mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));
    await run(["secret://k", "--imap-read-only", "--token", "jwt-value"]);
    expect(mockEngine.setInjectionPolicy).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ imap_read_only: true }),
      { acknowledge_interpreters: false },
      expect.objectContaining({ principal_id: "agent-1", interface: "cli" }),
    );
  });
});
