import {
  chmodSync,
  closeSync,
  existsSync,
  fchmodSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ErrorCode, MAX_TOKEN_TTL_MS, VaultError } from "@harpoc/shared";

const { mockEngine, MINTED_JTI, MINTED_TOKEN } = vi.hoisted(() => {
  const jti = "019a0000-0000-7000-8000-000000000001";
  const part = (value: object): string =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const token = `${part({ alg: "HS256", typ: "JWT" })}.${part({ jti })}.c2lnbmF0dXJl`;
  return {
    MINTED_JTI: jti,
    MINTED_TOKEN: token,
    mockEngine: {
      createToken: vi.fn().mockReturnValue(token),
      revokeToken: vi.fn(),
      destroy: vi.fn().mockResolvedValue(undefined),
    },
  };
});

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    openSync: vi.fn(actual.openSync),
    closeSync: vi.fn(actual.closeSync),
    writeSync: vi.fn(actual.writeSync),
    unlinkSync: vi.fn(actual.unlinkSync),
    fchmodSync: vi.fn(actual.fchmodSync),
  };
});

import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerAuthTokenCommand } from "./token.js";
import { readLaunchTokenFile } from "@harpoc/mcp-server";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";
import { expectAbsent } from "@harpoc/test-utils";

const run = buildCli(
  (program) => registerAuthTokenCommand(program.command("auth")),
  ["auth", "token"],
);
const NODE_TEXT = "node-own-text-5b1d";
const JTI_LINE = /^JTI\s+019a0000-0000-7000-8000-000000000001$/m;
const FLAG_AS_PATH =
  "Error: [INVALID_INPUT] --out: a flag, not a path (give a path that starts with a dash as ./-name)";

function codedError(code: string): NodeJS.ErrnoException {
  const err: NodeJS.ErrnoException = new Error(`${code}: ${NODE_TEXT}`);
  err.code = code;
  return err;
}

/** The next `closeSync` closes the real descriptor and then throws: win32 removes no file a handle holds. */
async function failCloseOnce(code: string): Promise<void> {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  vi.mocked(closeSync).mockImplementationOnce((fd) => {
    actual.closeSync(fd);
    throw codedError(code);
  });
}

describe("auth token --principal-type", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
  });

  it("defaults the principal type to agent", async () => {
    await run(["--agent", "bot-1"]);
    expect(mockEngine.createToken).toHaveBeenCalledWith("bot-1", ["use", "list"], 60 * 60_000, {
      project: undefined,
      secrets: undefined,
      principalType: "agent",
      label: undefined,
    });
  });

  // I28 (test-review-2026-10-09): getting-started documents `--project` and
  // `--ttl <minutes>`; with no --scope the token carries the default use,list.
  it("--project and an accepted --ttl reach createToken; no --scope mints use,list (I28)", async () => {
    await run(["--agent", "bot-1", "--project", "api", "--ttl", "480"]);
    expect(mockEngine.createToken).toHaveBeenCalledTimes(1);
    expect(mockEngine.createToken).toHaveBeenCalledWith("bot-1", ["use", "list"], 480 * 60_000, {
      project: "api",
      secrets: undefined,
      principalType: "agent",
      label: undefined,
    });
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
    const output = spies.errorSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(output).toContain('Invalid principal type: "project"');
    expect(output).toContain("Valid: agent, tool, user");
  });

  it("refuses a non-integer --ttl as an INVALID_INPUT envelope under --json (P1cF-3)", async () => {
    await expect(run(["--ttl", "1e3", "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: "TTL must be a positive number of minutes",
    });
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("--ttl is parsed before the vault opens: a typo on a locked vault reports INVALID_INPUT (D1d-5)", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(
      new VaultError(ErrorCode.VAULT_LOCKED, "Vault is locked"),
    );
    try {
      await expect(run(["--ttl", "5abc", "--json"])).rejects.toThrow("process.exit");
      expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
        error: "INVALID_INPUT",
        message: "TTL must be a positive number of minutes",
      });
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    } finally {
      vi.mocked(loadUnlockedEngine).mockReset();
      vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
    }
  });

  it("a --ttl over the cap is refused as an INVALID_INPUT envelope under --json (P1cF-3)", async () => {
    const maxTtlMinutes = Math.floor(MAX_TOKEN_TTL_MS / 60_000);
    await expect(run(["--ttl", String(maxTtlMinutes + 1), "--json"])).rejects.toThrow(
      "process.exit",
    );
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: `TTL cannot exceed ${maxTtlMinutes} minutes (${maxTtlMinutes / 60}h)`,
    });
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("an unknown --scope permission is refused as an INVALID_INPUT envelope under --json (P1cF-3)", async () => {
    await expect(run(["--scope", "bogus", "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: 'Invalid permission: "bogus". Valid: list, read, use, create, rotate, revoke, admin',
    });
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("an invalid --principal-type is refused as an INVALID_INPUT envelope under --json (P1cF-3)", async () => {
    await expect(run(["--principal-type", "project", "--json"])).rejects.toThrow("process.exit");
    expect(JSON.parse(String(spies.errorSpy.mock.calls[0]?.[0]))).toEqual({
      error: "INVALID_INPUT",
      message: 'Invalid principal type: "project". Valid: agent, tool, user',
    });
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });
});

describe("auth token --label", () => {
  let spies: CliSpies;

  beforeEach(() => {
    vi.clearAllMocks();
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
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
    await run(["--agent", "bot-1", "--label", "ci-launch-7f3a"]);
    expect(spies.stdout()).toMatch(/^Label\s+ci-launch-7f3a$/m);
  });

  it("prints the label under --json", async () => {
    await run(["--agent", "bot-1", "--label", "ci", "--json"]);
    const payload = JSON.parse(spies.stdout()) as { label: string | null };
    expect(payload.label).toBe("ci");
  });

  it("prints a null label under --json when the flag is absent", async () => {
    await run(["--agent", "bot-1", "--json"]);
    const payload = JSON.parse(spies.stdout()) as { label: string | null };
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
  let spies: CliSpies;
  let dir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    dir = mkdtempSync(join(tmpdir(), "harpoc-auth-out-"));
    spies = spyCli();
  });

  afterEach(() => {
    spies.restore();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("writes the token to --out and prints no token", async () => {
    const out = join(dir, "launch-token");
    await run(["--agent", "bot-1", "--out", out]);

    expect(readFileSync(out, "utf8")).toBe(`${MINTED_TOKEN}\n`);
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expect(spies.stderr()).toContain(`Token written to ${out}`);
    expect(spies.stdout()).toContain("Subject");
    expect(spies.stdout()).toMatch(JTI_LINE);
  });

  it("puts token_file in place of token under --json", async () => {
    const out = join(dir, "launch-token.json-mode");
    await run(["--agent", "bot-1", "--out", out, "--json"]);

    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    const payload = JSON.parse(spies.stdout()) as {
      token?: string;
      token_file?: string;
      jti?: string;
    };
    expect(payload.token_file).toBe(out);
    expect(payload.token).toBeUndefined();
    expect(payload.jti).toBe(MINTED_JTI);
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
  });

  it("both output forms print the JTI", async () => {
    await run(["--agent", "bot-1"]);
    expect(spies.stdout()).toMatch(JTI_LINE);

    spies.logSpy.mockClear();
    await run(["--agent", "bot-1", "--json"]);
    const printed = JSON.parse(spies.stdout()) as { token?: string; jti?: string };
    expect(printed.jti).toBe(MINTED_JTI);
    expect(printed.token).toBe(MINTED_TOKEN);

    spies.logSpy.mockClear();
    await run(["--agent", "bot-1", "--out", join(dir, "plain-form")]);
    expect(spies.stdout()).toMatch(JTI_LINE);

    spies.logSpy.mockClear();
    const jsonOut = join(dir, "json-form");
    await run(["--agent", "bot-1", "--out", jsonOut, "--json"]);
    const written = JSON.parse(spies.stdout()) as { token_file?: string; jti?: string };
    expect(written.jti).toBe(MINTED_JTI);
    expect(written.token_file).toBe(jsonOut);
  });

  it("refuses an existing --out path before the token is minted", async () => {
    const out = join(dir, "already-there");
    writeFileSync(out, "keep-me\n", "utf8");

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.stderr()).toContain("INVALID_INPUT");
    expect(spies.stderr()).toContain(out);
    expect(mockEngine.createToken).not.toHaveBeenCalled();
    expect(readFileSync(out, "utf8")).toBe("keep-me\n");
  });

  it.each([
    {
      label: "an unknown --scope permission",
      args: () => ["--scope", "use,bogus"],
      line: () =>
        'Error: [INVALID_INPUT] Invalid permission: "bogus". Valid: list, read, use, create, rotate, revoke, admin',
    },
    {
      label: "an unknown --principal-type",
      args: () => ["--principal-type", "robot"],
      line: () =>
        'Error: [INVALID_INPUT] Invalid principal type: "robot". Valid: agent, tool, user',
    },
    {
      label: "an empty --out",
      args: () => ["--out", ""],
      line: () => "Error: [INVALID_INPUT] --out: empty path",
    },
    {
      label: "a flag taken as the --out path",
      args: () => ["--out", "--json"],
      line: () => FLAG_AS_PATH,
    },
    { label: "a dash-led --out= value", args: () => ["--out=-k"], line: () => FLAG_AS_PATH },
    {
      label: "an --out whose directory does not exist",
      args: () => ["--out", join(dir, "no-such-dir", "launch-token")],
      line: () => `Error: [INVALID_INPUT] --out: no such directory: ${join(dir, "no-such-dir")}`,
    },
    {
      label: "an existing --out file",
      args: () => {
        writeFileSync(join(dir, "already-there"), "keep-me\n", "utf8");
        return ["--out", join(dir, "already-there")];
      },
      line: () =>
        `Error: [INVALID_INPUT] --out: ${join(dir, "already-there")} exists; the token is written to a new file only`,
    },
  ])("refuses $label before the vault opens", async ({ args, line }) => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(
      new VaultError(ErrorCode.VAULT_LOCKED, "Vault is locked"),
    );
    try {
      await expect(run(["--agent", "bot-1", ...args()])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([[line()]]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(mockEngine.createToken).not.toHaveBeenCalled();
    } finally {
      vi.mocked(loadUnlockedEngine).mockReset();
      vi.mocked(loadUnlockedEngine).mockResolvedValue(mockEngine as never);
    }
  });

  it("--out --json writes no file named --json", async () => {
    const stray = resolve("--json");
    try {
      await expect(run(["--agent", "bot-1", "--out", "--json"])).rejects.toThrow("process.exit");
      expect(spies.errorSpy.mock.calls).toEqual([[FLAG_AS_PATH]]);
      expect(existsSync(stray)).toBe(false);
      expect(mockEngine.createToken).not.toHaveBeenCalled();
    } finally {
      rmSync(stray, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("a failed create carries the path and the errno code", async () => {
    const out = join(dir, "launch-token");
    vi.mocked(openSync).mockImplementationOnce(() => {
      throw codedError("EACCES");
    });

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (EACCES)`],
    ]);
    expect(mockEngine.createToken).not.toHaveBeenCalled();

    spies.errorSpy.mockClear();
    vi.mocked(openSync).mockImplementationOnce(() => {
      throw codedError("EACCES");
    });
    await expect(run(["--agent", "bot-1", "--out", out, "--json"])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        JSON.stringify({
          error: "FILE_IO_ERROR",
          message: `could not write the token file ${out} (EACCES)`,
        }),
      ],
    ]);
    expect(mockEngine.createToken).not.toHaveBeenCalled();
  });

  it("a failed write after the mint carries the path and the errno code, the token in neither stream", async () => {
    const out = join(dir, "launch-token");
    vi.mocked(writeSync).mockImplementationOnce(() => {
      throw codedError("ENOSPC");
    });

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (ENOSPC)`],
    ]);
    expect(mockEngine.createToken).toHaveBeenCalledTimes(1);
    expect(existsSync(out)).toBe(false);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);

    spies.errorSpy.mockClear();
    mockEngine.revokeToken.mockClear();
    const jsonOut = join(dir, "launch-token.json-mode");
    vi.mocked(writeSync).mockImplementationOnce(() => {
      throw codedError("ENOSPC");
    });
    await expect(run(["--agent", "bot-1", "--out", jsonOut, "--json"])).rejects.toThrow(
      "process.exit",
    );
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        JSON.stringify({
          error: "FILE_IO_ERROR",
          message: `could not write the token file ${jsonOut} (ENOSPC)`,
        }),
      ],
    ]);
    expect(existsSync(jsonOut)).toBe(false);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);
  });

  it("a failed close after the write carries the path and the errno code", async () => {
    const out = join(dir, "launch-token");
    await failCloseOnce("EDQUOT");

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (EDQUOT)`],
    ]);
    expect(closeSync).toHaveBeenCalledTimes(1);
    expect(existsSync(out)).toBe(false);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);

    spies.errorSpy.mockClear();
    mockEngine.revokeToken.mockClear();
    const jsonOut = join(dir, "launch-token.json-mode");
    await failCloseOnce("EDQUOT");
    await expect(run(["--agent", "bot-1", "--out", jsonOut, "--json"])).rejects.toThrow(
      "process.exit",
    );
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        JSON.stringify({
          error: "FILE_IO_ERROR",
          message: `could not write the token file ${jsonOut} (EDQUOT)`,
        }),
      ],
    ]);
    expect(closeSync).toHaveBeenCalledTimes(2);
    expect(existsSync(jsonOut)).toBe(false);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);
  });

  it("a failed close behind a failed write leaves the write's errno code", async () => {
    const out = join(dir, "launch-token");
    vi.mocked(writeSync).mockImplementationOnce(() => {
      throw codedError("ENOSPC");
    });
    await failCloseOnce("EIO");

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (ENOSPC)`],
    ]);
    expect(closeSync).toHaveBeenCalledTimes(1);
    expect(existsSync(out)).toBe(false);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);
  });

  it("a short write is FILE_IO_ERROR (short write): the file is removed and the minted token revoked", async () => {
    const out = join(dir, "launch-token");
    const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
    vi.mocked(writeSync).mockImplementationOnce(((fd: number, buffer: Buffer) =>
      actual.writeSync(fd, buffer, 0, 5)) as typeof writeSync);

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (short write)`],
    ]);
    expect(existsSync(out)).toBe(false);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);
    expect(mockEngine.revokeToken.mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(unlinkSync).mock.invocationCallOrder[0] as number,
    );
  });

  it("a short write of the whole token less its line feed is still a failure", async () => {
    const out = join(dir, "launch-token");
    const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
    vi.mocked(writeSync).mockImplementationOnce(((fd: number, buffer: Buffer) =>
      actual.writeSync(fd, buffer, 0, buffer.length - 1)) as typeof writeSync);

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (short write)`],
    ]);
    expect(existsSync(out)).toBe(false);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);
  });

  it("a failed revoke warns with the JTI and the code and still removes the file", async () => {
    const out = join(dir, "launch-token");
    vi.mocked(writeSync).mockImplementationOnce(() => {
      throw codedError("ENOSPC");
    });
    mockEngine.revokeToken.mockImplementationOnce(() => {
      throw VaultError.vaultLocked();
    });

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        `Warning: the token ${MINTED_JTI} could not be revoked (VAULT_LOCKED); revoke it with: harpoc auth revoke ${MINTED_JTI}`,
      ],
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (ENOSPC)`],
    ]);
    expect(existsSync(out)).toBe(false);
  });

  it("a failed removal after a failed write warns with the path and the errno code", async () => {
    const out = join(dir, "launch-token");
    vi.mocked(writeSync).mockImplementationOnce(() => {
      throw codedError("ENOSPC");
    });
    vi.mocked(unlinkSync).mockImplementationOnce(() => {
      throw codedError("EPERM");
    });

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Warning: could not remove ${out} after the failed write (EPERM)`],
      [`Error: [FILE_IO_ERROR] could not write the token file ${out} (ENOSPC)`],
    ]);
    expect(mockEngine.revokeToken.mock.calls).toEqual([[MINTED_JTI]]);
  });

  it("a retry with the same --out after a failed write is served", async () => {
    const out = join(dir, "launch-token");
    vi.mocked(writeSync).mockImplementationOnce(() => {
      throw codedError("ENOSPC");
    });
    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");

    spies.errorSpy.mockClear();
    await run(["--agent", "bot-1", "--out", out]);
    expect(readFileSync(out, "utf8")).toBe(`${MINTED_TOKEN}\n`);
    expect(spies.errorSpy.mock.calls).toEqual([[`Token written to ${out}`]]);
  });

  it("a failed removal after a refused mint warns with the path and the errno code", async () => {
    const out = join(dir, "refused-mint");
    mockEngine.createToken.mockImplementationOnce(() => {
      throw VaultError.agentNotFound("bot-1");
    });
    vi.mocked(unlinkSync).mockImplementationOnce(() => {
      throw codedError("EPERM");
    });

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Warning: could not remove the empty ${out} after the token was refused (EPERM)`],
      [
        'Error: [AGENT_NOT_FOUND] Agent not registered: "bot-1". Register it with: harpoc agent register bot-1',
      ],
    ]);
  });

  it("a failed close after a refused mint does not hide the refusal", async () => {
    const out = join(dir, "refused-mint");
    mockEngine.createToken.mockImplementationOnce(() => {
      throw VaultError.agentNotFound("bot-1");
    });
    await failCloseOnce("EIO");

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        'Error: [AGENT_NOT_FOUND] Agent not registered: "bot-1". Register it with: harpoc agent register bot-1',
      ],
    ]);
    expect(closeSync).toHaveBeenCalledTimes(1);
    expect(existsSync(out)).toBe(false);
  });

  // The owner-only repair is skipped on win32 (the file inherits the directory's ACL there).
  it.runIf(process.platform !== "win32")(
    "a failed owner-only repair warns with the path and the errno code",
    async () => {
      const out = join(dir, "mode-repair");
      vi.mocked(fchmodSync).mockImplementationOnce(() => {
        throw codedError("EPERM");
      });

      await run(["--agent", "bot-1", "--out", out]);
      expectAbsent(spies.stderr(), NODE_TEXT, "stderr");
      expect(spies.errorSpy.mock.calls).toEqual([
        [`Warning: could not restrict ${out} to owner-only access (EPERM)`],
        [`Token written to ${out}`],
      ]);
    },
  );

  it("removes the opened file when the mint itself is refused", async () => {
    const out = join(dir, "refused-mint");
    mockEngine.createToken.mockImplementationOnce(() => {
      throw new Error("Agent not found: bot-1");
    });

    await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(existsSync(out)).toBe(false);
    expectAbsent(spies.stdout(), MINTED_TOKEN, "stdout");
    expectAbsent(spies.stderr(), MINTED_TOKEN, "stderr");
    // The happy unlink path is silent: the warning is for an unlink that failed.
    expect(spies.stderr()).not.toContain("could not remove the empty");
    expect(mockEngine.revokeToken).not.toHaveBeenCalled();
  });

  it.runIf(process.platform !== "win32")("writes it 0600 on POSIX", async () => {
    const out = join(dir, "mode-checked");
    await run(["--agent", "bot-1", "--out", out]);
    expect(statSync(out).mode & 0o777).toBe(0o600);
  });

  // Symbolic links: win32 refuses one without a privilege (EPERM); POSIX makes one freely.
  it.skipIf(process.platform === "win32")(
    "refuses a dangling symlink at --out as an existing entry before the vault opens and writes nothing through it",
    async () => {
      const out = join(dir, "planted-link");
      const target = join(dir, "missing-target");
      symlinkSync(target, out);

      await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
      expectAbsent(spies.stdout(), MINTED_TOKEN);
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [`Error: [INVALID_INPUT] --out: ${out} exists; the token is written to a new file only`],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(existsSync(target)).toBe(false);
      expect(mockEngine.createToken).not.toHaveBeenCalled();
    },
  );

  // POSIX modes: win32 has none, and root searches a 0600 directory regardless.
  it.skipIf(process.platform === "win32" || process.geteuid?.() === 0)(
    "refuses an --out it cannot check (its directory not searchable) before the vault opens, without errno text (POSIX)",
    async () => {
      const locked = join(dir, "locked");
      const out = join(locked, "launch-token");
      mkdirSync(locked);
      chmodSync(locked, 0o600);
      try {
        await expect(run(["--agent", "bot-1", "--out", out])).rejects.toThrow("process.exit");
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([
          [`Error: [INVALID_INPUT] --out: cannot check ${out} (is its directory searchable?)`],
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
        expect(mockEngine.createToken).not.toHaveBeenCalled();
      } finally {
        chmodSync(locked, 0o700);
      }
    },
  );

  it("round-trips through readLaunchTokenFile, the consumer of the file", async () => {
    const out = join(dir, "round-trip");
    await run(["--agent", "bot-1", "--out", out]);
    expect(readLaunchTokenFile(out)).toEqual({ ok: true, token: MINTED_TOKEN });
  });
});
