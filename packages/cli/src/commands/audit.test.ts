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

import { ErrorCode, VaultError } from "@harpoc/shared";
import { loadUnlockedEngine } from "../utils/vault-loader.js";
import { registerAuditCommand } from "./audit.js";
import { buildCli, spyCli, type CliSpies } from "../__fixtures__/cli-harness.js";

const run = buildCli(registerAuditCommand, ["audit"]);

describe("audit --since validation", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("rejects an unparseable --since instead of silently returning the full list", async () => {
    await expect(run(["--since", "banana", "--json"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("--since must be a valid date"),
    );
    expect(mockEngine.queryAudit).not.toHaveBeenCalled();
  });

  it("passes a valid --since to the engine as an epoch timestamp", async () => {
    await run(["--since", "2026-07-01", "--json"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ since: new Date("2026-07-01").getTime() }),
      undefined,
    );
  });

  it("omits since entirely when --since is not given", async () => {
    await run(["--json"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ since: undefined }),
      undefined,
    );
  });

  it("refuses a non-decimal --limit as an INVALID_INPUT envelope under --json (P1cF-4)", async () => {
    await expect(run(["--limit", "0x10", "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: "--limit must be a positive number",
    });
    expect(mockEngine.queryAudit).not.toHaveBeenCalled();
  });

  it("--limit is parsed before the vault opens: a typo on a locked vault reports INVALID_INPUT (D1d-5)", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(
      new VaultError(ErrorCode.VAULT_LOCKED, "Vault is locked"),
    );
    try {
      await expect(run(["--limit", "5abc", "--json"])).rejects.toThrow("process.exit");
      expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
        error: "INVALID_INPUT",
        message: "--limit must be a positive number",
      });
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    } finally {
      vi.mocked(loadUnlockedEngine).mockReset();
      vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
    }
  });

  it("an invalid --since is refused as an INVALID_INPUT envelope under --json (P1cF-4)", async () => {
    await expect(run(["--since", "bogus", "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: "--since must be a valid date (e.g. 2026-07-01 or 2026-07-01T12:00:00Z)",
    });
    expect(mockEngine.queryAudit).not.toHaveBeenCalled();
  });

  it("refuses an empty --since instead of treating it as no filter (P1c-32)", async () => {
    await expect(run(["--since", "", "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: "--since must be a valid date (e.g. 2026-07-01 or 2026-07-01T12:00:00Z)",
    });
    expect(mockEngine.queryAudit).not.toHaveBeenCalled();
  });
});

describe("audit table Principal column (by whom, thesis §4.3.4)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

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
    const lines = spies.stdout().split("\n");
    const start = lines[0]?.indexOf("Principal") ?? -1;
    const end = lines[0]?.indexOf("IP") ?? -1;
    expect(start).toBeGreaterThan(-1);
    expect(lines[2]?.slice(start, end).trim()).toBe("agent:alice");
    expect(lines[3]?.slice(start, end).trim()).toBe("-");
    expect(spies.stdout()).not.toContain("local");
  });
});

/**
 * D8/R18: `ip_address` has been on the row since E75i (2026-09-02) and in
 * `--json` since, but the table showed seven of the eight "who and from where"
 * columns. The Web UI table gains the same column in the same position.
 */
describe("audit table IP column (from where, E75i)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  // printTable pads every cell, so two or more spaces separate columns and
  // nothing inside a cell (the timestamp's single space included) splits.
  const cells = (line: string): string[] => line.trim().split(/\s{2,}/);

  it("renders the socket peer after Principal and '-' for a NULL one", async () => {
    mockEngine.queryAudit.mockReturnValue([
      {
        id: 1,
        timestamp: 1784306411000,
        event_type: "secret.read",
        secret_id: "s-1",
        principal_type: "agent",
        principal_id: "alice",
        ip_address: "127.0.0.1",
        detail: { interface: "rest" },
        session_id: "sess-1234567890",
        success: true,
      },
      {
        id: 2,
        timestamp: 1784306412000,
        event_type: "secret.read",
        secret_id: "s-2",
        principal_type: "agent",
        principal_id: "bob",
        ip_address: null,
        detail: { interface: "cli" },
        session_id: "sess-2234567890",
        success: true,
      },
    ]);

    await run([]);
    const lines = spies.logSpy.mock.calls
      .map((c) => c.join(" "))
      .join("\n")
      .split("\n");
    expect(cells(lines[0] ?? "")).toEqual([
      "ID",
      "Time",
      "Event",
      "Secret",
      "Principal",
      "IP",
      "Session",
      "Success",
    ]);
    expect(cells(lines[2] ?? "")[5]).toBe("127.0.0.1");
    expect(cells(lines[3] ?? "")[5]).toBe("-");
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
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), "harpoc-anchor-test-"));
    spies = spyCli();
    process.exitCode = undefined;
  });

  afterEach(() => {
    spies.restore();
    process.exitCode = undefined;
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("prints the anchor JSON to stdout and the off-host guidance to stderr", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
    await run(["anchor"]);
    expect(JSON.parse(spies.stdout())).toEqual(validAnchor);
    expect(spies.stderr()).toContain("OFF-HOST");
    expect(spies.stdout()).not.toContain("OFF-HOST");
  });

  it("writes the anchor to --out and keeps stdout clean", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
    const out = join(tempDir, "vault.anchor");
    await run(["anchor", "--out", out]);
    expect(JSON.parse(readFileSync(out, "utf8"))).toEqual(validAnchor);
    expect(spies.logSpy).not.toHaveBeenCalled();
    expect(spies.stderr()).toContain("Anchor written to");
    expect(spies.stderr()).toContain("OFF-HOST");
  });

  it("exits non-zero when there are no chained rows to anchor", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(null);
    await expect(run(["anchor"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.stderr()).toContain("No anchorable audit chain tail");
  });

  it("verify always prints the current tail link, without and with --json", async () => {
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: true,
      checked: 3,
      firstBrokenId: null,
      tail: validAnchor,
    });
    await run(["verify"]);
    expect(spies.stdout()).toContain(`Tail link: row ${validAnchor.last_id}`);
    expect(spies.stdout()).toContain(validAnchor.row_hmac);
    expect(spies.stdout()).toContain("Audit chain OK — 3 row(s) verified.");

    spies.logSpy.mockClear();
    await run(["verify", "--json"]);
    const json = JSON.parse(spies.stdout()) as { tail?: { last_id: number } };
    expect(json.tail?.last_id).toBe(validAnchor.last_id);
  });

  it("verify --anchor parses the file and passes the anchor to the engine", async () => {
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: true,
      checked: 3,
      firstBrokenId: null,
      tail: validAnchor,
      anchor: { lastId: validAnchor.last_id, status: "ok" },
    });
    const file = join(tempDir, "a.anchor");
    writeFileSync(file, JSON.stringify(validAnchor), "utf8");
    await run(["verify", "--anchor", file]);
    expect(mockEngine.verifyAuditChain).toHaveBeenCalledWith({ anchor: validAnchor });
    expect(spies.stdout()).toContain(`Anchor OK — row ${validAnchor.last_id} intact`);
    expect(process.exitCode).toBeUndefined();
  });

  it("verify --anchor reports truncation and exits 1", async () => {
    mockEngine.verifyAuditChain.mockReturnValue({
      valid: false,
      checked: 2,
      firstBrokenId: null,
      tail: { ...validAnchor, last_id: 40 },
      anchor: { lastId: validAnchor.last_id, status: "row_missing" },
    });
    const file = join(tempDir, "a.anchor");
    writeFileSync(file, JSON.stringify(validAnchor), "utf8");
    await run(["verify", "--anchor", file]);
    expect(spies.stderr()).toContain("FAILS the anchor check");
    expect(spies.stderr()).toContain("deleted or the database was rolled back");
    expect(process.exitCode).toBe(1);
  });

  it("rejects a missing anchor file with a clean error before calling the engine", async () => {
    await expect(run(["verify", "--anchor", join(tempDir, "nope.anchor")])).rejects.toThrow(
      "process.exit",
    );
    expect(spies.stderr()).toContain("Cannot read anchor file");
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });

  it("rejects a non-JSON anchor file with a clean error", async () => {
    const file = join(tempDir, "bad.anchor");
    writeFileSync(file, "not json {", "utf8");
    await expect(run(["verify", "--anchor", file])).rejects.toThrow("process.exit");
    expect(spies.stderr()).toContain("not valid JSON");
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });

  it("rejects JSON that is not a harpoc anchor with a clean error", async () => {
    const file = join(tempDir, "wrong.anchor");
    writeFileSync(file, JSON.stringify({ hello: "world" }), "utf8");
    await expect(run(["verify", "--anchor", file])).rejects.toThrow("process.exit");
    expect(spies.stderr()).toContain("Not a valid harpoc audit anchor");
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });

  it("a missing anchor file is refused as an INVALID_INPUT envelope under --json (P1cF-4)", async () => {
    const file = join(tempDir, "nope.anchor");
    await expect(run(["verify", "--anchor", file, "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: `Cannot read anchor file: ${file}`,
    });
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });

  it("a non-JSON anchor file is refused as an INVALID_INPUT envelope under --json (P1cF-4)", async () => {
    const file = join(tempDir, "bad.anchor");
    writeFileSync(file, "not json {", "utf8");
    await expect(run(["verify", "--anchor", file, "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: `Anchor file is not valid JSON: ${file}`,
    });
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });

  it("JSON that is not a harpoc anchor is refused as an INVALID_INPUT envelope under --json (P1cF-4)", async () => {
    const file = join(tempDir, "wrong.anchor");
    writeFileSync(file, JSON.stringify({ hello: "world" }), "utf8");
    await expect(run(["verify", "--anchor", file, "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: `Not a valid harpoc audit anchor (expected format "harpoc-audit-anchor/1"): ${file}`,
    });
    expect(mockEngine.verifyAuditChain).not.toHaveBeenCalled();
  });
});
