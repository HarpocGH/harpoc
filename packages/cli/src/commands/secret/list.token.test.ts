import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    listSecrets: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretListCommand } from "./list.js";

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

describe("secret list — token path", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.listSecrets.mockReturnValue([
      { ...INFO, name: "db-key" },
      { ...INFO, name: "mail-key", handle: "secret://mail-key" },
    ]);
    mockEngine.verifyToken.mockReturnValue(token());
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    // See the matching note in get.token.test.ts — a blanket
    // vi.restoreAllMocks() here also clobbers the vi.mock'd loadUnlockedEngine.
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
    registerSecretListCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "list", ...args]);
  }

  it("tokenless path is unchanged", async () => {
    await run([]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith(undefined, undefined);
  });

  it("passes the caller and defaults the project filter to the token's project", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["list"], project: "api" }));
    await run(["--token", "jwt-value"]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith("api", {
      principal_type: "agent",
      principal_id: "agent-1",
      project: "api",
      interface: "cli",
    });
  });

  it("refuses a cross-project --project against a project-scoped token", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["list"], project: "api" }));
    await expect(run(["--project", "other", "--token", "jwt-value"])).rejects.toThrow(
      "process.exit",
    );
    expect(mockEngine.listSecrets).not.toHaveBeenCalled();
  });

  it("treats --project '' as absent (H4) — the token's project still applies", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["list"], project: "api" }));
    await run(["--project", "", "--token", "jwt-value"]);
    expect(mockEngine.listSecrets).toHaveBeenCalledWith("api", expect.anything());
  });

  it('tokenless --project "" keeps its fail-closed empty filter (no normalization)', async () => {
    mockEngine.listSecrets.mockReturnValue([]);
    await run(["--project", ""]);
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.listSecrets).toHaveBeenCalledWith("", undefined);
  });

  it("filters results by the token's secret-name patterns", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["list"], secrets: ["db-*"] }));
    await run(["--json", "--token", "jwt-value"]);
    const printed = JSON.parse(
      (console.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0])).join("\n"),
    ) as Array<{ name: string }>;
    expect(printed.map((s) => s.name)).toEqual(["db-key"]);
  });
});
