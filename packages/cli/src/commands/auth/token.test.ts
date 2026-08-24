import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    createToken: vi.fn().mockReturnValue("jwt-token"),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { Command } from "commander";
import { registerAuthTokenCommand } from "./token.js";

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const auth = program.command("auth");
  registerAuthTokenCommand(auth);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "auth", "token", ...args]);
}

describe("auth token --principal-type", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
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
  });

  it("defaults the principal type to agent", async () => {
    await run(["--agent", "bot-1"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith(
      "bot-1",
      expect.any(Array),
      expect.any(Number),
      expect.objectContaining({ principalType: "agent" }),
    );
  });

  it("passes --principal-type tool through to createToken", async () => {
    await run(["--agent", "ci-pipeline", "--principal-type", "tool"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith(
      "ci-pipeline",
      expect.any(Array),
      expect.any(Number),
      expect.objectContaining({ principalType: "tool" }),
    );
  });

  it("rejects an invalid principal type with a clean message before reaching the engine", async () => {
    await expect(run(["--principal-type", "project"])).rejects.toThrow("process.exit");
    expect(mockEngine.createToken).not.toHaveBeenCalled();
    const output = errorSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(output).toContain('Invalid principal type: "project"');
    expect(output).toContain("Valid: agent, tool, user");
  });
});

describe("auth token --label", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  const stdout = (): string => logSpy.mock.calls.map((c) => String(c[0])).join("\n");

  beforeEach(() => {
    vi.clearAllMocks();
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
  });

  it("passes the label through to createToken", async () => {
    await run(["--agent", "bot-1", "--label", "ci"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith(
      "bot-1",
      expect.any(Array),
      expect.any(Number),
      expect.objectContaining({ label: "ci" }),
    );
  });

  it("passes no label when the flag is absent", async () => {
    await run(["--agent", "bot-1"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith(
      "bot-1",
      expect.any(Array),
      expect.any(Number),
      expect.objectContaining({ label: undefined }),
    );
  });

  it("prints the label in the human output", async () => {
    await run(["--agent", "bot-1", "--label", "ci"]);
    const out = stdout();
    expect(out).toContain("Label");
    expect(out).toContain("ci");
  });

  it("prints the label under --json", async () => {
    await run(["--agent", "bot-1", "--label", "ci", "--json"]);
    const payload = JSON.parse(stdout()) as { label: string | null };
    expect(payload.label).toBe("ci");
  });

  it("prints a null label under --json when the flag is absent", async () => {
    await run(["--agent", "bot-1", "--json"]);
    const payload = JSON.parse(stdout()) as { label: string | null };
    expect(payload.label).toBeNull();
  });
});
