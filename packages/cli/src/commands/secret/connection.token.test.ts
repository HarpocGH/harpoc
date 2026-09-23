import { rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { Command } from "commander";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    getConnectionConfig: vi.fn(),
    setConnectionConfig: vi.fn(),
    deleteConnectionConfig: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerSecretConnectionCommand } from "./connection.js";

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

describe("secret connection — token path", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.getConnectionConfig.mockResolvedValue({
      database: { tls_mode: "require" },
    });
    mockEngine.setConnectionConfig.mockResolvedValue(undefined);
    mockEngine.deleteConnectionConfig.mockResolvedValue(true);
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
    registerSecretConnectionCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "connection", ...args]);
  }

  it("--delete requires rotate and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--delete", "--token", "jwt-value"]);
    expect(mockEngine.deleteConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("show requires read and passes the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await run(["secret://k", "--show", "--token", "jwt-value"]);
    expect(mockEngine.getConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set requires rotate — a read-scoped token is refused before any engine call", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expect(
      run(["secret://k", "--db-tls", "require", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.setConnectionConfig).not.toHaveBeenCalled();
  });

  it("set mode's merge read rides the write's permission and names the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--db-tls", "require", "--token", "jwt-value"]);
    expect(mockEngine.getConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ interface: "cli" }),
      { forPermission: "rotate" },
    );
    expect(mockEngine.setConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ database: expect.objectContaining({ tls_mode: "require" }) }),
      expect.objectContaining({ interface: "cli" }),
    );
  });

  it("set passes the caller; tokenless set passes none", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await run(["secret://k", "--db-tls", "require", "--token", "jwt-value"]);
    expect(mockEngine.setConnectionConfig).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ database: expect.objectContaining({ tls_mode: "require" }) }),
      expect.objectContaining({ interface: "cli" }),
    );
    await run(["secret://k", "--db-tls", "require"]);
    expect(mockEngine.setConnectionConfig).toHaveBeenLastCalledWith(
      "secret://k",
      expect.anything(),
      undefined,
    );
  });

  it("renders a schema refusal value-free through the shared renderer", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["rotate"] }));
    await expect(
      run(["secret://conn", "--db-tls", "bogus", "--token", "jwt-value"]),
    ).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("database.tls_mode: must be one of require, disable"),
    );
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("bogus"));
    expect(mockEngine.setConnectionConfig).not.toHaveBeenCalled();
  });

  it.each([["--db-ca-file"], ["--known-hosts-file"], ["--mail-ca"], ["--git-ca"], ["--http-ca"]])(
    "%s with an empty path is refused INVALID_INPUT before the vault opens (P1F-4)",
    async (flag) => {
      await expect(run(["secret://k", flag, "", "--json"])).rejects.toThrow("process.exit");
      expect(JSON.parse(String(errorSpy.mock.calls[0]?.[0]))).toEqual({
        error: "INVALID_INPUT",
        message: `${flag} requires a file path.`,
      });
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    },
  );

  it("a whitespace-only path is refused INVALID_INPUT before the vault opens (P1F-4)", async () => {
    await expect(run(["secret://k", "--git-ca", "  ", "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: "--git-ca requires a file path.",
    });
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it.each([["--db-ca-file"], ["--known-hosts-file"], ["--mail-ca"], ["--git-ca"], ["--http-ca"]])(
    "%s with a nonexistent path is refused INVALID_INPUT before the vault opens (P1c-31)",
    async (flag) => {
      await expect(
        run(["secret://k", flag, "C:/nonexistent/harpoc-1c.pem", "--json"]),
      ).rejects.toThrow("process.exit");
      expect(JSON.parse(String(errorSpy.mock.calls[0]?.[0]))).toEqual({
        error: "INVALID_INPUT",
        message: `${flag}: no such file: C:/nonexistent/harpoc-1c.pem`,
      });
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    },
  );

  it("--http-ca <file> merges the http group over the stored config (D2h)", async () => {
    const caPath = join(tmpdir(), `harpoc-http-ca-${process.pid}.pem`);
    writeFileSync(caPath, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    try {
      await run(["secret://k", "--http-ca", caPath]);
      expect(mockEngine.setConnectionConfig).toHaveBeenCalledWith(
        "secret://k",
        {
          database: { tls_mode: "require" },
          http: { ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" },
        },
        undefined,
      );
    } finally {
      rmSync(caPath, { force: true });
    }
  });
});
