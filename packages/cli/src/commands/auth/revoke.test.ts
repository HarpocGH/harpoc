import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

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
import { registerAuthRevokeCommand } from "./revoke.js";

function jwtWithExp(exp: number): string {
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url");
  return `header.${payload}.signature`;
}

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const auth = program.command("auth");
  registerAuthRevokeCommand(auth);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "auth", "revoke", ...args]);
}

describe("auth revoke token sources", () => {
  const savedEnv = process.env.HARPOC_TOKEN;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.HARPOC_TOKEN;
    } else {
      process.env.HARPOC_TOKEN = savedEnv;
    }
    logSpy.mockRestore();
  });

  it("extracts the expiry from HARPOC_TOKEN when --token is not given", async () => {
    process.env.HARPOC_TOKEN = jwtWithExp(12345);
    await run(["some-jti"]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti", 12345);
  });

  it("an explicit --token wins over HARPOC_TOKEN", async () => {
    process.env.HARPOC_TOKEN = jwtWithExp(11111);
    await run(["some-jti", "--token", jwtWithExp(22222)]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti", 22222);
  });

  it("revokes without an expiry when no token is available anywhere", async () => {
    await run(["some-jti"]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti", undefined);
  });
});
