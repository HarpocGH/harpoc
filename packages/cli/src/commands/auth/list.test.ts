import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { IssuedToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    listIssuedTokens: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { Command } from "commander";
import { registerAuthListCommand } from "./list.js";

const TOKEN: IssuedToken = {
  jti: "01960000-0000-7000-8000-0000000000aa",
  subject: "bot",
  principal_type: "agent",
  agent: "bot",
  scope: ["use", "list"],
  project: null,
  secrets: null,
  label: "ci",
  issued_at: 1_700_000_000_000,
  expires_at: 1_700_003_600_000,
  revoked_at: null,
  status: "active",
};

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const auth = program.command("auth");
  registerAuthListCommand(auth);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "auth", "list", ...args]);
}

describe("harpoc auth list", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  const stdout = (): string => logSpy.mock.calls.map((c) => String(c[0])).join("\n");

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.listIssuedTokens.mockReturnValue([TOKEN]);

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

  it("lists active tokens by default", async () => {
    await run([]);
    expect(mockEngine.listIssuedTokens).toHaveBeenCalledWith(
      { agent: undefined, status: "active" },
      undefined,
    );
  });

  it("lists every token under --all", async () => {
    await run(["--all"]);
    expect(mockEngine.listIssuedTokens).toHaveBeenCalledWith(
      { agent: undefined, status: "all" },
      undefined,
    );
  });

  it("filters by agent", async () => {
    await run(["--agent", "bot"]);
    expect(mockEngine.listIssuedTokens).toHaveBeenCalledWith(
      { agent: "bot", status: "active" },
      undefined,
    );
  });

  it("prints the documented table columns", async () => {
    await run([]);
    const out = stdout();
    for (const column of [
      "JTI",
      "Subject",
      "Type",
      "Agent",
      "Scope",
      "Label",
      "Issued",
      "Expires",
      "Status",
    ]) {
      expect(out).toContain(column);
    }
    expect(out).toContain(TOKEN.jti);
  });

  it("prints the engine return verbatim under --json", async () => {
    await run(["--json"]);
    expect(logSpy).toHaveBeenCalledWith(JSON.stringify([TOKEN], null, 2));
  });

  it("never prints a JWT — the registry holds claims metadata only", async () => {
    await run(["--json"]);
    expect(stdout()).not.toContain("eyJ");
  });
});
