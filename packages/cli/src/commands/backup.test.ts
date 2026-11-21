import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";

const { mockEngine, mockAssertOwnerOnlyDir, mockIsHeldPath } = vi.hoisted(() => ({
  mockEngine: {
    backupToFile: vi.fn(),
    destroy: vi.fn(),
  },
  mockAssertOwnerOnlyDir: vi.fn(),
  mockIsHeldPath: vi.fn(),
}));

vi.mock("../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));
vi.mock("@harpoc/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@harpoc/core")>();
  return {
    ...actual,
    assertOwnerOnlyDir: mockAssertOwnerOnlyDir,
    isHeldPath: mockIsHeldPath.mockImplementation(actual.isHeldPath),
  };
});

import { loadUnlockedEngine } from "../utils/vault-loader.js";
import { registerBackupCommand } from "./backup.js";
import { buildCli, spyCli, type CliSpies } from "../__fixtures__/cli-harness.js";
import { icacls } from "../__fixtures__/icacls.js";

const WIN32 = process.platform === "win32";
const USERS = "S-1-5-32-545";
const FLAG_AS_PATH = "<file>: a flag, not a path (give a path that starts with a dash as ./-name)";
const CHANGEABLE = "<file>: a directory on its path can be changed by another account";

const run = buildCli((program) => registerBackupCommand(program), ["backup"]);

async function runIn(cwd: string, args: string[]): Promise<void> {
  const spy = vi.spyOn(process, "cwd").mockReturnValue(cwd);
  try {
    await run(args);
  } finally {
    spy.mockRestore();
  }
}

let dir: string;
let target: string;
let spies: CliSpies;

beforeEach(() => {
  vi.clearAllMocks();
  dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-backup-")));
  target = join(dir, "vault-copy.db");
  mockEngine.backupToFile.mockImplementation(async (file: string) => ({ file }));
  mockEngine.destroy.mockResolvedValue(undefined);
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
  mockAssertOwnerOnlyDir.mockReset();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("harpoc backup <file>", () => {
  it("asks the engine for a copy at the resolved path and prints that path", async () => {
    await runIn(dir, ["vault-copy.db"]);

    expect(vi.mocked(loadUnlockedEngine).mock.calls).toEqual([["/mock/.harpoc"]]);
    expect(mockEngine.backupToFile.mock.calls).toEqual([
      [target, { signal: expect.any(AbortSignal) }],
    ]);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
    const order = [mockEngine.backupToFile, mockEngine.destroy].map(
      (mock) => mock.mock.invocationCallOrder[0] as number,
    );
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(spies.errorSpy.mock.calls).toEqual([[`OK: Backup written to ${target}`]]);
    expect(spies.logSpy).not.toHaveBeenCalled();
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("--json prints the copy's path as backup_file", async () => {
    await run([target, "--json"]);

    expect(mockEngine.backupToFile.mock.calls).toEqual([
      [target, { signal: expect.any(AbortSignal) }],
    ]);
    expect(spies.logSpy.mock.calls).toEqual([[JSON.stringify({ backup_file: target }, null, 2)]]);
    expect(spies.errorSpy).not.toHaveBeenCalled();
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  const refusals = [
    { label: "an empty path", args: () => [""], message: () => "<file>: empty path" },
    { label: "a dash-led path", args: () => ["-"], message: () => FLAG_AS_PATH },
    {
      label: "a file that exists",
      args: () => {
        writeFileSync(target, "");
        return [target];
      },
      message: () => `<file>: ${target} exists; a backup is written to a new file only`,
    },
    {
      label: "a file whose directory does not exist",
      args: () => [join(dir, "missing", "vault-copy.db")],
      message: () => `<file>: no such directory: ${join(dir, "missing")}`,
    },
  ];

  it.each(refusals)("refuses $label before the vault opens", async ({ args, message }) => {
    await expect(run(args())).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([[`Error: [INVALID_INPUT] ${message()}`]]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(mockAssertOwnerOnlyDir).not.toHaveBeenCalled();
    expect(mockEngine.backupToFile).not.toHaveBeenCalled();
  });

  it.each(refusals)(
    "under --json refuses $label with the envelope before the vault opens",
    async ({ args, message }) => {
      await expect(run([...args(), "--json"])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [JSON.stringify({ error: "INVALID_INPUT", message: message() })],
      ]);
      expect(spies.logSpy).not.toHaveBeenCalled();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(mockEngine.backupToFile).not.toHaveBeenCalled();
    },
  );

  it("refuses an existing file named by a relative path, the path as typed in the line", async () => {
    writeFileSync(target, "");

    await expect(runIn(dir, ["vault-copy.db"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      [
        "Error: [INVALID_INPUT] <file>: vault-copy.db exists; a backup is written to a new file only",
      ],
    ]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("backup -- -name is the dash refusal", async () => {
    await expect(run(["--", "-name"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([[`Error: [INVALID_INPUT] ${FLAG_AS_PATH}`]]);
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
  });

  it("a locked vault is VAULT_LOCKED and no file", async () => {
    vi.mocked(loadUnlockedEngine).mockRejectedValueOnce(VaultError.vaultLocked());

    await expect(run([target])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: Vault is locked. Run 'harpoc unlock' first."],
    ]);
    expect(mockEngine.backupToFile).not.toHaveBeenCalled();
    expect(existsSync(target)).toBe(false);
  });

  it.each(["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"] as const)(
    "%s during the copy aborts the engine's signal and the command ends only once the engine has answered",
    async (signal) => {
      const before = new Set(process.listeners(signal));
      const added = () => process.listeners(signal).filter((listener) => !before.has(listener));
      let enter: (handed: AbortSignal | undefined) => void = () => undefined;
      const entered = new Promise<AbortSignal | undefined>((resolve) => {
        enter = resolve;
      });
      let answer: (err: unknown) => void = () => undefined;
      mockEngine.backupToFile.mockImplementationOnce(
        (_file: string, options?: { signal?: AbortSignal }) => {
          enter(options?.signal);
          return new Promise((_resolve, reject) => {
            answer = reject;
          });
        },
      );
      let ended = false;
      const running = run([target]).finally(() => {
        ended = true;
      });

      const handed = await entered;
      expect(handed?.aborted).toBe(false);
      expect(added()).toHaveLength(1);
      (added()[0] as (name: string) => void)(signal);
      expect(handed?.aborted).toBe(true);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(ended).toBe(false);
      expect(mockEngine.destroy).not.toHaveBeenCalled();
      expect(spies.exitSpy).not.toHaveBeenCalled();

      answer(VaultError.databaseError("backup did not finish"));
      await expect(running).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        ["Error: [DATABASE_ERROR] Database error: backup did not finish"],
      ]);
      expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
      expect(added()).toEqual([]);
    },
  );

  it("the engine is destroyed when the copy fails", async () => {
    const failure = new VaultError(
      ErrorCode.FILE_IO_ERROR,
      "could not write the backup (the copy is not closed to other accounts)",
    );
    mockEngine.backupToFile.mockRejectedValueOnce(failure);

    await expect(run([target])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([[`Error: [FILE_IO_ERROR] ${failure.message}`]]);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  // Windows: a file created in a directory another account can read is open to it before the vault closes it.
  it.runIf(WIN32)(
    "a directory another account can read is refused before the vault opens (win32)",
    async () => {
      const actual = await vi.importActual<typeof import("@harpoc/core")>("@harpoc/core");
      mockAssertOwnerOnlyDir.mockImplementationOnce(actual.assertOwnerOnlyDir);
      icacls(dir, "/grant", `*${USERS}:(OI)(CI)R`);

      await expect(run([target])).rejects.toThrow("process.exit");
      expect(mockAssertOwnerOnlyDir.mock.calls).toEqual([[dir, "<file>"]]);
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          `Error: [INVALID_INPUT] <file>: the access list grants ${USERS} 0x00120089; only this process's account, SYSTEM and Administrators may hold a grant: ${dir}`,
        ],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(existsSync(target)).toBe(false);
    },
  );

  // Windows: a closed directory whose parent another account can delete can be swapped from above.
  it.runIf(WIN32)(
    "a closed directory under a directory another account can delete is refused before the vault opens (win32)",
    async () => {
      const actual = await vi.importActual<typeof import("@harpoc/core")>("@harpoc/core");
      mockAssertOwnerOnlyDir.mockImplementationOnce(actual.assertOwnerOnlyDir);
      const open = join(dir, "open");
      mkdirSync(open);
      icacls(open, "/grant", `*${USERS}:(D)`);
      const closed = join(open, "backups");
      mkdirSync(closed);

      await expect(run([join(closed, "vault-copy.db")])).rejects.toThrow("process.exit");
      expect(mockAssertOwnerOnlyDir.mock.calls).toEqual([[closed, "<file>"]]);
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([[`Error: [INVALID_INPUT] ${CHANGEABLE}`]]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(existsSync(join(closed, "vault-copy.db"))).toBe(false);
    },
  );

  // Windows: the directory's own access list refuses first where the directories above it are not held either.
  it.runIf(WIN32)(
    "a directory another account can read, under a directory another account can delete, is refused with the directory's own refusal before the vault opens (win32)",
    async () => {
      const actual = await vi.importActual<typeof import("@harpoc/core")>("@harpoc/core");
      mockAssertOwnerOnlyDir.mockImplementationOnce(actual.assertOwnerOnlyDir);
      const open = join(dir, "open");
      mkdirSync(open);
      icacls(open, "/grant", `*${USERS}:(D)`);
      const shared = join(open, "backups");
      mkdirSync(shared);
      icacls(shared, "/grant", `*${USERS}:(OI)(CI)R`);

      await expect(run([join(shared, "vault-copy.db")])).rejects.toThrow("process.exit");
      expect(mockIsHeldPath.mock.invocationCallOrder[0] as number).toBeLessThan(
        mockAssertOwnerOnlyDir.mock.invocationCallOrder[0] as number,
      );
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          `Error: [INVALID_INPUT] <file>: the access list grants ${USERS} 0x00120089; only this process's account, SYSTEM and Administrators may hold a grant: ${shared}`,
        ],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(existsSync(join(shared, "vault-copy.db"))).toBe(false);
    },
  );

  // A junction needs no privilege, and only win32 refuses a link as the target's directory itself.
  it.runIf(WIN32)(
    "a target whose directory is itself a junction is refused with the link line before the directories above it are judged (win32)",
    async () => {
      const real = join(dir, "real");
      mkdirSync(real);
      const link = join(dir, "link");
      symlinkSync(real, link, "junction");

      await expect(run([join(link, "vault-copy.db")])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          `Error: [INVALID_INPUT] <file>: the path is a symbolic link or junction, not a directory: ${link}`,
        ],
      ]);
      expect(mockIsHeldPath).not.toHaveBeenCalled();
      expect(mockAssertOwnerOnlyDir).not.toHaveBeenCalled();
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    },
  );

  // Windows: the directory's access list is read once the directories above it are held, not before.
  it.runIf(WIN32)(
    "a directory that stops being closed while the directories above it are judged is refused before the vault opens (win32)",
    async () => {
      const actual = await vi.importActual<typeof import("@harpoc/core")>("@harpoc/core");
      mockAssertOwnerOnlyDir.mockImplementationOnce(actual.assertOwnerOnlyDir);
      mockIsHeldPath.mockImplementationOnce(async (file: string) => {
        const held = await actual.isHeldPath(file);
        icacls(dir, "/grant", `*${USERS}:(OI)(CI)R`);
        return held;
      });

      await expect(run([target])).rejects.toThrow("process.exit");
      expect(mockIsHeldPath.mock.calls).toEqual([[target]]);
      expect(mockAssertOwnerOnlyDir.mock.calls).toEqual([[dir, "<file>"]]);
      expect(mockIsHeldPath.mock.invocationCallOrder[0] as number).toBeLessThan(
        mockAssertOwnerOnlyDir.mock.invocationCallOrder[0] as number,
      );
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [
          `Error: [INVALID_INPUT] <file>: the access list grants ${USERS} 0x00120089; only this process's account, SYSTEM and Administrators may hold a grant: ${dir}`,
        ],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(existsSync(target)).toBe(false);
    },
  );

  // POSIX modes: an account that can write a directory on the path can replace the copy's temporary file; win32 judges the access list above.
  it.skipIf(WIN32)(
    "a directory another account can write is refused before the vault opens (POSIX)",
    async () => {
      chmodSync(dir, 0o777);

      await expect(run([target])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([[`Error: [INVALID_INPUT] ${CHANGEABLE}`]]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
      expect(mockEngine.backupToFile).not.toHaveBeenCalled();
      expect(existsSync(target)).toBe(false);
    },
  );

  // POSIX modes, as the row above.
  it.skipIf(WIN32)(
    "under --json a directory another account can write is refused with the envelope before the vault opens (POSIX)",
    async () => {
      chmodSync(dir, 0o777);

      await expect(run([target, "--json"])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [JSON.stringify({ error: "INVALID_INPUT", message: CHANGEABLE })],
      ]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    },
  );

  // POSIX modes: off Windows the path is walked for write access and the directory is not judged owner-only.
  it.skipIf(WIN32)(
    "no owner-only judgement is made and a 0755 directory passes the walk (POSIX)",
    async () => {
      const actual = await vi.importActual<typeof import("@harpoc/core")>("@harpoc/core");
      mockAssertOwnerOnlyDir.mockImplementationOnce(actual.assertOwnerOnlyDir);
      chmodSync(dir, 0o755);

      await run([target]);

      expect(mockAssertOwnerOnlyDir).not.toHaveBeenCalled();
      expect(mockEngine.backupToFile.mock.calls).toEqual([
        [target, { signal: expect.any(AbortSignal) }],
      ]);
      expect(spies.errorSpy.mock.calls).toEqual([[`OK: Backup written to ${target}`]]);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    },
  );

  // POSIX symbolic links: win32 judges a link or junction as the directory itself, owner-only.
  it.skipIf(WIN32)(
    "a target typed through a link is judged by the directory the link names (POSIX)",
    async () => {
      const real = join(dir, "real");
      mkdirSync(real);
      chmodSync(real, 0o755);
      const link = join(dir, "link");
      symlinkSync(real, link);

      await run([join(link, "vault-copy.db")]);

      expect(mockEngine.backupToFile.mock.calls).toEqual([
        [join(real, "vault-copy.db"), { signal: expect.any(AbortSignal) }],
      ]);
      expect(spies.errorSpy.mock.calls).toEqual([
        [`OK: Backup written to ${join(real, "vault-copy.db")}`],
      ]);
      expect(spies.exitSpy).not.toHaveBeenCalled();
    },
  );

  // POSIX symbolic links and modes, as the row above.
  it.skipIf(WIN32)(
    "a target typed through a link to a directory another account can write is refused before the vault opens (POSIX)",
    async () => {
      const shared = join(dir, "shared");
      mkdirSync(shared);
      chmodSync(shared, 0o777);
      const link = join(dir, "link");
      symlinkSync(shared, link);

      await expect(run([join(link, "vault-copy.db")])).rejects.toThrow("process.exit");
      expect(spies.exitSpy.mock.calls).toEqual([[1]]);
      expect(spies.errorSpy.mock.calls).toEqual([[`Error: [INVALID_INPUT] ${CHANGEABLE}`]]);
      expect(loadUnlockedEngine).not.toHaveBeenCalled();
    },
  );

  // POSIX modes: win32 has none, and root searches a 0000 directory regardless.
  it.skipIf(WIN32 || process.geteuid?.() === 0)(
    "a file it cannot check, its directory not searchable, is refused before the vault opens (POSIX)",
    async () => {
      const locked = join(dir, "locked");
      mkdirSync(locked);
      chmodSync(locked, 0o000);
      const file = join(locked, "vault-copy.db");
      try {
        await expect(run([file])).rejects.toThrow("process.exit");
        expect(spies.exitSpy.mock.calls).toEqual([[1]]);
        expect(spies.errorSpy.mock.calls).toEqual([
          [`Error: [INVALID_INPUT] <file>: cannot check ${file} (is its directory searchable?)`],
        ]);
        expect(loadUnlockedEngine).not.toHaveBeenCalled();
      } finally {
        chmodSync(locked, 0o700);
      }
    },
  );
});
