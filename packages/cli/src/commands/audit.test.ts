import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from "vitest";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    queryAudit: vi.fn().mockReturnValue([]),
    getAuditChainTail: vi.fn(),
    verifyAuditChain: vi.fn(),
    verifyToken: vi.fn(),
    auditGovernanceRefusal: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, writeFileSync: vi.fn(actual.writeFileSync) };
});

import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { loadUnlockedEngine } from "../utils/vault-loader.js";
import { registerAuditCommand } from "./audit.js";
import { buildCli, spyCli, tokenFixture, type CliSpies } from "../__fixtures__/cli-harness.js";

const run = buildCli(registerAuditCommand, ["audit"]);

const SECRET_ID = "0190c9d2-7b4a-7c3e-8f12-3456789abcde";
const NODE_TEXT = "node-own-text-7c2e";

function codedError(code: string): NodeJS.ErrnoException {
  const err: NodeJS.ErrnoException = new Error(`${code}: ${NODE_TEXT}`);
  err.code = code;
  return err;
}

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
      undefined,
    );
  });

  it("omits since entirely when --since is not given", async () => {
    await run(["--json"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ since: undefined }),
      undefined,
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

// I29 (test-review-2026-10-09): getting-started documents `audit --secret <id>`.
describe("audit --secret (I29)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("--secret reaches queryAudit as secretId, the other filters at their defaults", async () => {
    await run(["--secret", SECRET_ID, "--json"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledTimes(1);
    expect(mockEngine.queryAudit).toHaveBeenCalledWith(
      {
        secretId: SECRET_ID,
        eventType: undefined,
        excludeEventType: undefined,
        since: undefined,
        limit: 50,
      },
      undefined,
      undefined,
    );
  });
});

describe("audit --exclude-event (A-9)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("--exclude-event reaches queryAudit as excludeEventType, the trusted path passing no caller", async () => {
    await run(["--exclude-event", "vault.read", "--json"]);
    expect(mockEngine.queryAudit).toHaveBeenCalledTimes(1);
    expect(mockEngine.queryAudit.mock.calls).toEqual([
      [
        {
          secretId: undefined,
          eventType: undefined,
          excludeEventType: "vault.read",
          since: undefined,
          limit: 50,
        },
        undefined,
        undefined,
      ],
    ]);
  });
});

const FILTER_REFUSALS = [
  {
    kind: "unknown",
    option: "--event",
    typed: "secret.raed",
    message: "--event: not an audit event type",
  },
  {
    kind: "unknown",
    option: "--exclude-event",
    typed: "secret.raed",
    message: "--exclude-event: not an audit event type",
  },
  {
    kind: "unknown",
    option: "--secret",
    typed: "not-an-id",
    message: "--secret: not a secret id",
  },
  {
    kind: "empty",
    option: "--event",
    typed: "",
    message: "--event: not an audit event type",
  },
  {
    kind: "empty",
    option: "--secret",
    typed: "",
    message: "--secret: not a secret id",
  },
];

describe("audit's filters are judged before the vault opens (C-11)", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it.each(FILTER_REFUSALS)(
    "refuses an $kind $option value as the fixed INVALID_INPUT envelope, nothing opened",
    async ({ option, typed, message }) => {
      await expect(run([option, typed, "--json"])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(typed !== "" && `${spies.stdout()}\n${spies.stderr()}`.includes(typed)).toBe(false);
      expect(spies.errorSpy.mock.calls).toEqual([
        [JSON.stringify({ error: "INVALID_INPUT", message })],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(mockEngine.queryAudit).not.toHaveBeenCalled();
    },
  );

  it.each(FILTER_REFUSALS)(
    "on a locked vault an $kind $option value still reports INVALID_INPUT, not VAULT_LOCKED",
    async ({ option, typed, message }) => {
      vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(
        new VaultError(ErrorCode.VAULT_LOCKED, "Vault is locked"),
      );
      try {
        await expect(run([option, typed, "--json"])).rejects.toThrow("process.exit");
        expect(typed !== "" && `${spies.stdout()}\n${spies.stderr()}`.includes(typed)).toBe(false);
        expect(spies.errorSpy.mock.calls).toEqual([
          [JSON.stringify({ error: "INVALID_INPUT", message })],
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      } finally {
        vi.mocked(loadUnlockedEngine).mockReset();
        vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
      }
    },
  );

  it.each([
    ["--event", "eventType"],
    ["--exclude-event", "excludeEventType"],
  ] as const)(
    "every AuditEventType member passes %s and reaches queryAudit as %s (Review Focus 7)",
    async (option, key) => {
      const members = Object.values(AuditEventType);
      for (const member of members) {
        await run([option, member, "--json"]);
      }
      expect(spies.exitSpy).not.toHaveBeenCalled();
      expect(
        mockEngine.queryAudit.mock.calls.map((call) => (call[0] as Record<string, unknown>)[key]),
      ).toEqual(members);
    },
  );
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
    expect(mockEngine.getAuditChainTail.mock.calls).toEqual([[undefined]]);
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

  it.each([
    {
      label: "an empty --out",
      args: () => ["anchor", "--out", ""],
      line: () => "Error: [INVALID_INPUT] --out: empty path",
    },
    {
      label: "a dash-led --out=--json value",
      args: () => ["anchor", "--out=--json"],
      line: () =>
        "Error: [INVALID_INPUT] --out: a flag, not a path (give a path that starts with a dash as ./-name)",
    },
    {
      label: "an --out whose directory does not exist",
      args: () => ["anchor", "--out", join(tempDir, "missing", "vault.anchor")],
      line: () => `Error: [INVALID_INPUT] --out: no such directory: ${join(tempDir, "missing")}`,
    },
    {
      label: "an existing --out file",
      args: () => {
        writeFileSync(join(tempDir, "vault.anchor"), "keep-me\n", "utf8");
        return ["anchor", "--out", join(tempDir, "vault.anchor")];
      },
      line: () =>
        `Error: [INVALID_INPUT] --out: ${join(tempDir, "vault.anchor")} exists; the anchor is written to a new file only`,
      kept: () => join(tempDir, "vault.anchor"),
    },
  ])("anchor refuses $label before the vault opens", async ({ args, line, kept }) => {
    mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
    const stray = resolve("--json");
    try {
      await expect(run(args())).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([[line()]]);
      expect(spies.logSpy).not.toHaveBeenCalled();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(existsSync(stray)).toBe(false);
      const keptFile = kept?.();
      if (keptFile !== undefined) expect(readFileSync(keptFile, "utf8")).toBe("keep-me\n");
    } finally {
      rmSync(stray, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  // Symbolic links: win32 refuses one without a privilege (EPERM); POSIX makes one freely.
  it.skipIf(process.platform === "win32")(
    "a dangling link at --out is an existing entry",
    async () => {
      mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
      const out = join(tempDir, "planted-link");
      const target = join(tempDir, "missing-target");
      symlinkSync(target, out);

      await expect(run(["anchor", "--out", out])).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([
        [`Error: [INVALID_INPUT] --out: ${out} exists; the anchor is written to a new file only`],
      ]);
      expect(spies.logSpy).not.toHaveBeenCalled();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(existsSync(target)).toBe(false);
    },
  );

  // POSIX modes: win32 has none, and root searches a 0600 directory regardless.
  it.skipIf(process.platform === "win32" || process.geteuid?.() === 0)(
    "an --out it cannot check",
    async () => {
      mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
      const locked = join(tempDir, "locked");
      const out = join(locked, "vault.anchor");
      mkdirSync(locked);
      chmodSync(locked, 0o600);
      try {
        await expect(run(["anchor", "--out", out])).rejects.toThrow("process.exit");
        expect(spies.errorSpy.mock.calls).toEqual([
          [`Error: [INVALID_INPUT] --out: cannot check ${out} (is its directory searchable?)`],
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      } finally {
        chmodSync(locked, 0o700);
      }
    },
  );

  it("a file that appears at --out after the check is not replaced: FILE_IO_ERROR with the path and EEXIST, both forms", async () => {
    const out = join(tempDir, "vault.anchor");
    mockEngine.getAuditChainTail.mockImplementationOnce(() => {
      writeFileSync(out, "planted\n", "utf8");
      return validAnchor;
    });

    await expect(run(["anchor", "--out", out])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the anchor file ${out} (EEXIST)`],
    ]);
    expect(readFileSync(out, "utf8")).toBe("planted\n");
    expect(loadUnlockedEngine).toHaveBeenCalledTimes(1);

    spies.errorSpy.mockClear();
    const jsonOut = join(tempDir, "vault.anchor.json-mode");
    mockEngine.getAuditChainTail.mockImplementationOnce(() => {
      writeFileSync(jsonOut, "planted\n", "utf8");
      return validAnchor;
    });
    await expect(run(["anchor", "--out", jsonOut, "--json"])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        JSON.stringify({
          error: "FILE_IO_ERROR",
          message: `could not write the anchor file ${jsonOut} (EEXIST)`,
        }),
      ],
    ]);
    expect(readFileSync(jsonOut, "utf8")).toBe("planted\n");
    expect(spies.logSpy).not.toHaveBeenCalled();
  });

  it("a write that fails after the create leaves the file, and the retry is refused", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
    const out = join(tempDir, "vault.anchor");
    const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
    vi.mocked(writeFileSync).mockImplementationOnce((file, data, options) => {
      actual.writeFileSync(file, String(data).slice(0, 8), options);
      throw codedError("ENOSPC");
    });

    await expect(run(["anchor", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the anchor file ${out} (ENOSPC)`],
    ]);
    expect(existsSync(out)).toBe(true);

    spies.errorSpy.mockClear();
    await expect(run(["anchor", "--out", out])).rejects.toThrow("process.exit");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [INVALID_INPUT] --out: ${out} exists; the anchor is written to a new file only`],
    ]);
    expect(loadUnlockedEngine).toHaveBeenCalledTimes(1);
  });

  it("exits non-zero when there are no chained rows to anchor", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(null);
    await expect(run(["anchor"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.stderr()).toContain("No anchorable audit chain tail");
  });

  it("a tail without a link is refused as a VAULT_CORRUPTED envelope under --json (C-13)", async () => {
    mockEngine.getAuditChainTail.mockReturnValue(null);
    await expect(run(["anchor", "--json"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "VAULT_CORRUPTED",
      message:
        "No anchorable audit chain tail — the log is empty or its last row carries no link (run harpoc audit verify).",
    });
    expect(spies.logSpy).not.toHaveBeenCalled();
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
    expect(mockEngine.verifyAuditChain).toHaveBeenCalledWith({ anchor: validAnchor }, undefined);
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

const SCOPED_CLAIMS: Array<[string, Partial<VaultApiToken>]> = [
  ["project", { project: "acme" }],
  ["secrets", { secrets: ["*"] }],
];

const ADMIN_CALLER = {
  principal_type: "agent",
  principal_id: "agent-1",
  interface: "cli",
  admin_scope: true,
};

const CHAIN_COMMANDS: Array<[string, () => Mock]> = [
  ["verify", () => mockEngine.verifyAuditChain],
  ["anchor", () => mockEngine.getAuditChainTail],
];

describe.each(CHAIN_COMMANDS)(
  "audit %s --token: the chain is vault-wide (C-12)",
  (command, reads) => {
    let spies: CliSpies;

    beforeEach(() => {
      vi.clearAllMocks();
      mockEngine.verifyAuditChain.mockReturnValue({
        valid: true,
        checked: 3,
        firstBrokenId: null,
        tail: validAnchor,
      });
      mockEngine.getAuditChainTail.mockReturnValue(validAnchor);
      spies = spyCli();
      process.exitCode = undefined;
    });

    afterEach(() => {
      spies.restore();
      process.exitCode = undefined;
    });

    it.each(SCOPED_CLAIMS)(
      "refuses a %s-claimed admin token ACCESS_DENIED with one governance row before the chain is read",
      async (_claim, claims) => {
        mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"], ...claims }));

        await expect(run([command, "--token", "jwt-value"])).rejects.toThrow("process.exit");

        expect(spies.exitSpy).toHaveBeenCalledWith(1);
        expect(spies.stderr()).toContain(
          "[ACCESS_DENIED] Access denied: governance requires an unscoped admin token",
        );
        expect(mockEngine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
        expect(mockEngine.auditGovernanceRefusal).toHaveBeenCalledWith(
          { ...ADMIN_CALLER, ...claims },
          `audit ${command}`,
        );
        expect(reads()).not.toHaveBeenCalled();
        expect(spies.logSpy).not.toHaveBeenCalled();
      },
    );

    it("renders the refusal as the ACCESS_DENIED envelope under --json", async () => {
      mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"], project: "acme" }));

      await expect(run([command, "--token", "jwt-value", "--json"])).rejects.toThrow(
        "process.exit",
      );

      expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
        error: "ACCESS_DENIED",
        message: "Access denied: governance requires an unscoped admin token",
      });
      expect(mockEngine.auditGovernanceRefusal).toHaveBeenCalledTimes(1);
      expect(reads()).not.toHaveBeenCalled();
    });

    it("still reads the chain for an unscoped admin token, with no governance row", async () => {
      mockEngine.verifyToken.mockReturnValue(tokenFixture({ scope: ["admin"] }));

      await run([command, "--token", "jwt-value"]);

      expect(reads()).toHaveBeenCalledTimes(1);
      expect(mockEngine.auditGovernanceRefusal).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();
    });
  },
);
