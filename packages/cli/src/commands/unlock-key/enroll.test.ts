import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";

const { mockEngine, mockPromptPassword, mockWriteUnlockKeyFile, mockWriteUnlockKeyDpapi } =
  vi.hoisted(() => ({
    mockEngine: {
      unlock: vi.fn(),
      unlockKeyStatus: vi.fn(),
      enrollUnlockKey: vi.fn(),
      destroy: vi.fn(),
    },
    mockPromptPassword: vi.fn(),
    mockWriteUnlockKeyFile: vi.fn(),
    mockWriteUnlockKeyDpapi: vi.fn(),
  }));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  createEngine: vi.fn().mockReturnValue(mockEngine),
}));
vi.mock("../../utils/prompt.js", () => ({ promptPassword: mockPromptPassword }));
// The owner-only writer is core's (the key source module); wipeBuffer stays the real one.
vi.mock("@harpoc/core", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@harpoc/core")>()),
  writeUnlockKeyFile: mockWriteUnlockKeyFile,
  writeUnlockKeyDpapi: mockWriteUnlockKeyDpapi,
}));

import { createEngine } from "../../utils/vault-loader.js";
import { registerUnlockKeyEnrollCommand } from "./enroll.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const PASSWORD = "enroll-master-pw-1";
/** The fixture key's bytes; the engine double hands out a fresh buffer of them per test. */
const KEY_BYTES = Array.from({ length: 32 }, (_, i) => 0x40 + i);
const FLAG_AS_PATH =
  "Error: [INVALID_INPUT] --out: a flag, not a path (give a path that starts with a dash as ./-name)";

const run = buildCli(
  (program) => registerUnlockKeyEnrollCommand(program.command("unlock-key")),
  ["unlock-key", "enroll"],
);

let dir: string;
let out: string;
let key: Uint8Array;
/** The bytes the writer received, copied at the call — before the command's wipe. */
let written: number[] | undefined;
let spies: CliSpies;

beforeEach(() => {
  vi.clearAllMocks();
  dir = mkdtempSync(join(tmpdir(), "harpoc-unlock-key-enroll-"));
  out = join(dir, "harpoc-unlock.key");
  key = Uint8Array.from(KEY_BYTES);
  written = undefined;
  mockPromptPassword.mockResolvedValue(PASSWORD);
  mockEngine.unlock.mockResolvedValue(undefined);
  mockEngine.unlockKeyStatus.mockResolvedValue({ enrolled: false });
  mockEngine.enrollUnlockKey.mockResolvedValue(key);
  mockEngine.destroy.mockResolvedValue(undefined);
  mockWriteUnlockKeyFile.mockImplementation(async (_path: string, bytes: Uint8Array) => {
    written = Array.from(bytes);
  });
  mockWriteUnlockKeyDpapi.mockImplementation(async (_path: string, bytes: Uint8Array) => {
    written = Array.from(bytes);
  });
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/**
 * No form of the key a CLI leak would take reached stdout or stderr: hex, base64, the decimal list
 * of a `Uint8Array` in a template string, `util.inspect`'s list, `JSON.stringify`'s object and the
 * raw bytes (this fixture's are printable), nor — whitespace removed — `util.inspect`'s multi-line
 * rendering of the array. Every assertion on the key is a boolean naming the form, so a red never
 * echoes a byte of it (two-identity.test.ts's form); a row sweeps before it asserts on the
 * captured output.
 */
function expectNoKeyBytes(): void {
  const bytes = Buffer.from(KEY_BYTES);
  const forms: [form: string, needle: string][] = [
    ["hex", bytes.toString("hex")],
    ["base64", bytes.toString("base64")],
    ["a decimal list", KEY_BYTES.join(",")],
    ["util.inspect's list", KEY_BYTES.join(", ")],
    ["a JSON object", JSON.stringify(new Uint8Array(KEY_BYTES))],
    ["raw bytes", bytes.toString("latin1")],
  ];
  for (const [form, needle] of forms) {
    expect(spies.stdout().includes(needle), `stdout carries the key as ${form}`).toBe(false);
    expect(spies.stderr().includes(needle), `stderr carries the key as ${form}`).toBe(false);
  }
  const decimal = KEY_BYTES.join(",");
  const stripped = (text: string): string => text.replace(/\s+/g, "");
  expect(
    stripped(spies.stdout()).includes(decimal),
    "stdout carries the key as an inspected array",
  ).toBe(false);
  expect(
    stripped(spies.stderr()).includes(decimal),
    "stderr carries the key as an inspected array",
  ).toBe(false);
}

/** The writer was called once, with --out and the engine's buffer itself (not a copy). */
function expectWrittenTo(path: string): void {
  const calls = mockWriteUnlockKeyFile.mock.calls;
  expect(calls).toHaveLength(1);
  expect(calls[0]?.[0]).toBe(path);
  expect(calls[0]?.[1] === key).toBe(true);
}

const isWiped = (bytes: Uint8Array): boolean => bytes.every((byte) => byte === 0);

describe("harpoc unlock-key enroll", () => {
  it("unlocks with the prompted password, enrols, writes the key to --out and wipes it", async () => {
    await run(["--out", out]);

    expectNoKeyBytes();
    expect(mockPromptPassword.mock.calls).toEqual([[]]);
    expect(vi.mocked(createEngine).mock.calls).toEqual([["/mock/.harpoc"]]);
    expect(mockEngine.unlock.mock.calls).toEqual([[PASSWORD]]);
    expect(mockEngine.enrollUnlockKey.mock.calls).toEqual([[]]);
    // The engine's buffer itself reaches the writer, whole, and is zeroed after the write.
    expectWrittenTo(out);
    expect(written !== undefined && Buffer.from(written).equals(Buffer.from(KEY_BYTES))).toBe(true);
    expect(isWiped(key)).toBe(true);
    const order = [
      mockEngine.unlock,
      mockEngine.unlockKeyStatus,
      mockEngine.enrollUnlockKey,
      mockWriteUnlockKeyFile,
      mockEngine.destroy,
    ].map((mock) => mock.mock.invocationCallOrder[0] as number);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        `OK: Unlock key enrolled: written to ${out} (owner-only). Seal it before use (systemd: deploy/linux/enroll-unlock-key.sh ${out}).`,
      ],
    ]);
    expect(spies.logSpy).not.toHaveBeenCalled();
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("an enrolled slot is replaced, and the line says the previous key no longer unlocks", async () => {
    mockEngine.unlockKeyStatus.mockResolvedValueOnce({
      enrolled: true,
      enrolledAt: "2026-11-01T09:00:00.000Z",
    });

    await run(["--out", out]);

    expectNoKeyBytes();
    expect(mockEngine.enrollUnlockKey).toHaveBeenCalledTimes(1);
    expectWrittenTo(out);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        `OK: Unlock key replaced: written to ${out} (owner-only); the previous key no longer unlocks the vault. Seal the new one and restart the daemon (systemd: deploy/linux/enroll-unlock-key.sh ${out}).`,
      ],
    ]);
  });

  it("a missing --out is Commander's required-option error, before the prompt", async () => {
    await expect(run([])).rejects.toMatchObject({
      code: "commander.missingMandatoryOptionValue",
      message: "error: required option '--out <path>' not specified",
    });
    expect(mockPromptPassword).not.toHaveBeenCalled();
    expect(createEngine).not.toHaveBeenCalled();
  });

  it.each([
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
      args: () => ["--out", join(dir, "missing", "harpoc-unlock.key")],
      line: () => `Error: [INVALID_INPUT] --out: no such directory: ${join(dir, "missing")}`,
    },
    {
      label: "an existing --out file",
      args: () => {
        writeFileSync(out, "");
        return ["--out", out];
      },
      line: () =>
        `Error: [INVALID_INPUT] --out: ${out} exists; the unlock key is written to a new file only`,
    },
  ])("refuses $label before the prompt, the vault or the slot", async ({ args, line }) => {
    await expect(run(args())).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([[line()]]);
    expect(mockPromptPassword).not.toHaveBeenCalled();
    expect(createEngine).not.toHaveBeenCalled();
    expect(mockWriteUnlockKeyFile).not.toHaveBeenCalled();
  });

  // Symbolic links: win32 refuses one without a privilege (EPERM); POSIX makes one freely.
  it.skipIf(process.platform === "win32")(
    "refuses an --out that is a dangling symbolic link as an existing entry (lstat, not stat) before the prompt (POSIX)",
    async () => {
      symlinkSync(join(dir, "nowhere"), out);

      await expect(run(["--out", out])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          `Error: [INVALID_INPUT] --out: ${out} exists; the unlock key is written to a new file only`,
        ],
      ]);
      expect(mockPromptPassword).not.toHaveBeenCalled();
      expect(createEngine).not.toHaveBeenCalled();
      expect(mockWriteUnlockKeyFile).not.toHaveBeenCalled();
    },
  );

  // POSIX modes: win32 has none, and root searches a 0600 directory regardless.
  it.skipIf(process.platform === "win32" || process.geteuid?.() === 0)(
    "refuses an --out it cannot check (its directory not searchable) before the prompt, without errno text (POSIX)",
    async () => {
      const locked = join(dir, "locked");
      mkdirSync(locked);
      chmodSync(locked, 0o600);
      try {
        await expect(run(["--out", join(locked, "harpoc-unlock.key")])).rejects.toThrow(
          "process.exit",
        );
        expect(spies.errorSpy.mock.calls).toEqual([
          [
            `Error: [INVALID_INPUT] --out: cannot check ${join(locked, "harpoc-unlock.key")} (is its directory searchable?)`,
          ],
        ]);
        expect(mockPromptPassword).not.toHaveBeenCalled();
      } finally {
        chmodSync(locked, 0o700);
      }
    },
  );

  it("a wrong password enrols nothing and writes nothing", async () => {
    mockEngine.unlock.mockRejectedValueOnce(VaultError.invalidPassword());

    await expect(run(["--out", out])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([["Error: Invalid password."]]);
    expect(mockEngine.enrollUnlockKey).not.toHaveBeenCalled();
    expect(mockWriteUnlockKeyFile).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("a write that fails after the enrolment still wipes the key and destroys the engine", async () => {
    const failure = new VaultError(ErrorCode.FILE_IO_ERROR, "Unlock key file could not be written");
    mockWriteUnlockKeyFile.mockRejectedValueOnce(failure);

    await expect(run(["--out", out])).rejects.toThrow("process.exit");
    expectNoKeyBytes();
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([[`Error: [FILE_IO_ERROR] ${failure.message}`]]);
    expect(isWiped(key)).toBe(true);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});

/** Run `fn` with `process.platform` reading `platform` (the DPAPI branch is win32's). */
async function onPlatform<T>(platform: NodeJS.Platform, fn: () => Promise<T>): Promise<T> {
  const original = process.platform;
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  try {
    return await fn();
  } finally {
    Object.defineProperty(process, "platform", { value: original, configurable: true });
  }
}

describe("harpoc unlock-key enroll --dpapi", () => {
  it("seals the engine's key through the DPAPI writer to --out, never the raw writer, wipes it and names the account and the start option", async () => {
    await onPlatform("win32", () => run(["--out", out, "--dpapi"]));

    expectNoKeyBytes();
    expect(mockEngine.unlock.mock.calls).toEqual([[PASSWORD]]);
    const calls = mockWriteUnlockKeyDpapi.mock.calls;
    expect(calls).toHaveLength(1);
    expect(calls[0]?.[0]).toBe(out);
    expect(calls[0]?.[1] === key).toBe(true);
    expect(written !== undefined && Buffer.from(written).equals(Buffer.from(KEY_BYTES))).toBe(true);
    expect(mockWriteUnlockKeyFile).not.toHaveBeenCalled();
    expect(isWiped(key)).toBe(true);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        `OK: Unlock key enrolled: sealed with DPAPI for ${userInfo().username} and written to ${out} (owner-only). The daemon reads it as the same account: server start --unlock-key-dpapi ${out}.`,
      ],
    ]);
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("over an enrolled slot the line says the previous key no longer unlocks and names the restart", async () => {
    mockEngine.unlockKeyStatus.mockResolvedValueOnce({
      enrolled: true,
      enrolledAt: "2026-11-01T09:00:00.000Z",
    });

    await onPlatform("win32", () => run(["--out", out, "--dpapi"]));

    expect(spies.errorSpy.mock.calls).toEqual([
      [
        `OK: Unlock key replaced: sealed with DPAPI for ${userInfo().username} and written to ${out} (owner-only); the previous key no longer unlocks the vault. Restart the daemon (server start --unlock-key-dpapi ${out}).`,
      ],
    ]);
  });

  it("off win32 --dpapi is refused INVALID_INPUT naming the platform, before the prompt, the vault or the slot", async () => {
    await expect(onPlatform("linux", () => run(["--out", out, "--dpapi"]))).rejects.toThrow(
      "process.exit",
    );
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Error: [INVALID_INPUT] --dpapi: DPAPI is Windows' own and this platform is linux (seal the raw key with this platform's sealer: deploy/linux/enroll-unlock-key.sh)",
      ],
    ]);
    expect(mockPromptPassword).not.toHaveBeenCalled();
    expect(createEngine).not.toHaveBeenCalled();
    expect(mockWriteUnlockKeyDpapi).not.toHaveBeenCalled();
  });

  it("without --dpapi the DPAPI writer is never called", async () => {
    await onPlatform("win32", () => run(["--out", out]));
    expectWrittenTo(out);
    expect(mockWriteUnlockKeyDpapi).not.toHaveBeenCalled();
  });

  it("a seal that fails after the enrolment still wipes the key and destroys the engine", async () => {
    const failure = new VaultError(ErrorCode.SESSION_FILE_ERROR, "DPAPI seal failed (exit 1)");
    mockWriteUnlockKeyDpapi.mockRejectedValueOnce(failure);

    await expect(onPlatform("win32", () => run(["--out", out, "--dpapi"]))).rejects.toThrow(
      "process.exit",
    );
    expectNoKeyBytes();
    expect(spies.errorSpy.mock.calls).toEqual([[`Error: [SESSION_FILE_ERROR] ${failure.message}`]]);
    expect(isWiped(key)).toBe(true);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });
});
