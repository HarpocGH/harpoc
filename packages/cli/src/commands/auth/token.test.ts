import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
import { readLaunchTokenFile } from "@harpoc/mcp-server";

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

/**
 * `--out` is the launch-token channel `harpoc server start --mcp --token-file`
 * and `harpoc-mcp --token-file` read (R9/A10): argv is world-readable for the
 * server's whole lifetime, so the token travels on disk at 0600 and never
 * through stdout, where a log pipe or a shell history would keep it.
 */
describe("auth token --out", () => {
  let exitSpy: MockInstance;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let dir: string;

  const stdout = (): string => logSpy.mock.calls.map((c) => String(c[0])).join("\n");
  const stderr = (): string => errorSpy.mock.calls.map((c) => String(c[0])).join("\n");

  beforeEach(() => {
    vi.clearAllMocks();
    dir = mkdtempSync(join(tmpdir(), "harpoc-auth-out-"));
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
    rmSync(dir, { recursive: true, force: true });
  });

  it("writes the token to --out and prints no token", async () => {
    const out = join(dir, "launch-token");
    await run(["--agent", "bot-1", "--out", out]);

    expect(readFileSync(out, "utf8")).toBe("jwt-token\n");
    expect(stdout()).not.toContain("jwt-token");
    expect(stderr()).toContain(`Token written to ${out}`);
    expect(stdout()).toContain("Subject");
  });

  it("puts token_file in place of token under --json", async () => {
    const out = join(dir, "launch-token.json-mode");
    await run(["--agent", "bot-1", "--out", out, "--json"]);

    const payload = JSON.parse(stdout()) as { token?: string; token_file?: string };
    expect(payload.token_file).toBe(out);
    expect(payload.token).toBeUndefined();
    expect(stdout()).not.toContain("jwt-token");
  });

  it("refuses an existing --out path before the token is minted", async () => {
    const out = join(dir, "already-there");
    writeFileSync(out, "keep-me\n", "utf8");

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(stderr()).toContain("INVALID_INPUT");
    expect(stderr()).toContain(out);
    expect(mockEngine.createToken).not.toHaveBeenCalled();
    expect(readFileSync(out, "utf8")).toBe("keep-me\n");
  });

  it("mints no token when the --out path cannot be opened (a missing directory)", async () => {
    const out = join(dir, "no-such-dir", "launch-token");

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(stderr()).toContain("ENOENT");
    expect(mockEngine.createToken).not.toHaveBeenCalled();
    expect(stdout()).not.toContain("jwt-token");
  });

  it("removes the opened file when the mint itself is refused", async () => {
    const out = join(dir, "refused-mint");
    mockEngine.createToken.mockImplementationOnce(() => {
      throw new Error("Agent not found: bot-1");
    });

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(existsSync(out)).toBe(false);
    expect(stdout()).not.toContain("jwt-token");
  });

  it.runIf(process.platform !== "win32")("writes it 0600 on POSIX", async () => {
    const out = join(dir, "mode-checked");
    await run(["--agent", "bot-1", "--out", out]);
    expect(statSync(out).mode & 0o777).toBe(0o600);
  });

  it.runIf(process.platform !== "win32")(
    "refuses a dangling symlink at --out and writes nothing through it",
    async () => {
      const out = join(dir, "planted-link");
      const target = join(dir, "missing-target");
      symlinkSync(target, out);

      await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
      expect(exitSpy).toHaveBeenCalledWith(1);
      expect(stderr()).toContain("EEXIST");
      expect(existsSync(target)).toBe(false);
      expect(mockEngine.createToken).not.toHaveBeenCalled();
      expect(stdout()).not.toContain("jwt-token");
    },
  );

  it("round-trips through readLaunchTokenFile, the consumer of the file", async () => {
    const out = join(dir, "round-trip");
    await run(["--agent", "bot-1", "--out", out]);
    expect(readLaunchTokenFile(out)).toEqual({ ok: true, token: "jwt-token" });
  });
});
