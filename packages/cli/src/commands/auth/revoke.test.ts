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

function jwtWithExp(exp: number, jti = "some-jti"): string {
  const payload = Buffer.from(JSON.stringify({ exp, jti })).toString("base64url");
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
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.HARPOC_TOKEN;
    } else {
      process.env.HARPOC_TOKEN = savedEnv;
    }
    logSpy.mockRestore();
    errSpy.mockRestore();
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

  // M1: HARPOC_TOKEN authenticates other commands too, so it is routinely a
  // token OTHER than the revocation target. Forwarding its (earlier) expiry
  // shortened or nullified the revocation entry.
  it("ignores the expiry of a token whose jti is not the revocation target", async () => {
    process.env.HARPOC_TOKEN = jwtWithExp(12345, "other-jti");
    await run(["some-jti"]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti", undefined);
  });

  it("warns when the supplied token is not the revocation target", async () => {
    await run(["some-jti", "--token", jwtWithExp(12345, "other-jti")]);
    const warned = errSpy.mock.calls.some(
      (call) => typeof call[0] === "string" && call[0].startsWith("Warning:"),
    );
    expect(warned).toBe(true);
  });

  it("ignores a matching-jti token that carries no numeric exp", async () => {
    const payload = Buffer.from(JSON.stringify({ jti: "some-jti" })).toString("base64url");
    await run(["some-jti", "--token", `header.${payload}.signature`]);
    expect(mockEngine.revokeToken).toHaveBeenCalledWith("some-jti", undefined);
  });
});
