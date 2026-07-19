import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    queryAudit: vi.fn().mockReturnValue([]),
    getAuditChainTail: vi.fn(),
    verifyAuditChain: vi.fn(),
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

describe("audit table Principal column (by whom, thesis §4.3.4)", () => {
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

  function tableText(): string {
    return logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
  }

  it("renders type:id for attributed rows and '-' for NULL principal columns (never 'local')", async () => {
    mockEngine.queryAudit.mockReturnValue([
      {
        id: 1,
        timestamp: 1784306411000,
        event_type: "secret.use",
        secret_id: "s-1",
        principal_type: "agent",
        principal_id: "alice",
        detail: { context: "process", interface: "rest" },
        session_id: "sess-1234567890",
        success: true,
      },
      {
        id: 2,
        timestamp: 1784306412000,
        event_type: "secret.use",
        secret_id: "s-1",
        principal_type: null,
        principal_id: null,
        detail: { context: "process" },
        session_id: "sess-1234567890",
        success: true,
      },
    ]);

    await run([]);
    const text = tableText();
    expect(text).toContain("Principal");
    expect(text).toContain("agent:alice");
    expect(text).not.toContain("local");
  });
});

const validAnchor = {
  format: "harpoc-audit-anchor/1",
  vault_id: "vault-a",
  last_id: 42,
  timestamp: 1784306411000,
  row_hmac: "ab".repeat(32),
};

describe("audit anchor / verify --anchor", () => {
  let tempDir: string;
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), "harpoc-anchor-test-"));
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    process.exitCode = undefined;
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    process.exitCode = undefined;
    rmSync(tempDir, { recursive: true, force: true });
  });

  function stderrText(): string {
    return errorSpy.mock.calls.map((c) => c.join(" ")).join("\n");
  }

  function stdoutText(): string {
    return logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
  }

  it("prints the anchor JSON to stdout and the off-host guidance to stderr", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
    await run(["anchor"]);
    expect(JSON.parse(stdoutText())).toEqual(validAnchor);
    expect(stderrText()).toContain("OFF-HOST");
    expect(stdoutText()).not.toContain("OFF-HOST");
  });

  it("writes the anchor to --out and keeps stdout clean", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
    const out = join(tempDir, "vault.anchor");
    await run(["anchor", "--out", out]);
    expect(JSON.parse(readFileSync(out, "utf8"))).toEqual(validAnchor);
    expect(logSpy).not.toHaveBeenCalled();
    expect(stderrText()).toContain("Anchor written to");
    expect(stderrText()).toContain("OFF-HOST");
  });

  it("exits non-zero when there are no chained rows to anchor", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(null);
    await expect(run(["anchor"])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(stderrText()).toContain("No chained audit rows to anchor yet");
  });

  it("verify always prints the current tail link, without and with --json", async () => {
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: true,
      checked: 3,
      legacy: 0,
      firstBrokenId: null,
      tail: validAnchor,
    });
    await run(["verify"]);
    expect(stdoutText()).toContain(`Tail link: row ${validAnchor.last_id}`);
    expect(stdoutText()).toContain(validAnchor.row_hmac);

    logSpy.mockClear();
    await run(["verify", "--json"]);
    const json = JSON.parse(stdoutText()) as { tail?: { last_id: number } };
    expect(json.tail?.last_id).toBe(validAnchor.last_id);
  });

  it("verify --anchor parses the file and passes the anchor to the engine", async () => {
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: true,
      checked: 3,
      legacy: 0,
      firstBrokenId: null,
      tail: validAnchor,
      anchor: { lastId: validAnchor.last_id, status: "ok" },
    });
    const file = join(tempDir, "a.anchor");
    writeFileSync(file, JSON.stringify(validAnchor), "utf8");
    await run(["verify", "--anchor", file]);
    expect(mockEngine.verifyAuditChain).toHaveBeenCalledWith({ anchor: validAnchor });
    expect(stdoutText()).toContain(`Anchor OK — row ${validAnchor.last_id} intact`);
    expect(process.exitCode).toBeUndefined();
  });

  it("verify --anchor reports truncation and exits 1", async () => {
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: false,
      checked: 2,
      legacy: 0,
      firstBrokenId: null,
      tail: { ...validAnchor, last_id: 40 },
      anchor: { lastId: validAnchor.last_id, status: "row_missing" },
    });
    const file = join(tempDir, "a.anchor");
    writeFileSync(file, JSON.stringify(validAnchor), "utf8");
    await run(["verify", "--anchor", file]);
    expect(stderrText()).toContain("FAILS the anchor check");
    expect(stderrText()).toContain("deleted or the database was rolled back");
    expect(process.exitCode).toBe(1);
  });

  it("rejects a missing anchor file with a clean error before calling the engine", async () => {
    await expect(run(["verify", "--anchor", join(tempDir, "nope.anchor")])).rejects.toThrow(
      "process.exit",
    );
    expect(stderrText()).toContain("Cannot read anchor file");
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });

  it("rejects a non-JSON anchor file with a clean error", async () => {
    const file = join(tempDir, "bad.anchor");
    writeFileSync(file, "not json {", "utf8");
    await expect(run(["verify", "--anchor", file])).rejects.toThrow("process.exit");
    expect(stderrText()).toContain("not valid JSON");
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });

  it("rejects JSON that is not a harpoc anchor with a clean error", async () => {
    const file = join(tempDir, "wrong.anchor");
    writeFileSync(file, JSON.stringify({ hello: "world" }), "utf8");
    await expect(run(["verify", "--anchor", file])).rejects.toThrow("process.exit");
    expect(stderrText()).toContain("Not a valid harpoc audit anchor");
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });
});
