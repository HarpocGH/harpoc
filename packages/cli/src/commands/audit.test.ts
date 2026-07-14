import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    queryAudit: vi.fn().mockReturnValue([]),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { Command } from "commander";
import { registerAuditCommand } from "./audit.js";

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  registerAuditCommand(program);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "audit", ...args]);
}

describe("audit --since validation", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
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

  it("rejects an unparseable --since instead of silently returning the full list", async () => {
    await expect(run(["--since", "banana", "--json"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--since must be a valid date"));
    expect(mockEngine.queryAudit).not.toHaveBeenCalled();
  });

  it("passes a valid --since to the engine as an epoch timestamp", async () => {
    await run(["--since", "2026-07-01", "--json"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ since: new Date("2026-07-01").getTime() }),
    );
  });

  it("omits since entirely when --since is not given", async () => {
    await run(["--json"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ since: undefined }),
    );
  });
});
