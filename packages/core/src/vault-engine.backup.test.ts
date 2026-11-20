import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";
import { ADMINISTRATORS_SID, SYSTEM_SID, listWindowsAclSync } from "./session/owner-only.js";
import type { WindowsAclListing } from "./session/owner-only.js";
import { assertHeldDir, assertOwnerOnlyDir, isHeldPath } from "./session/path-trust.js";
import { isBackupTempName } from "./storage/backup-names.js";
import { SqliteStore } from "./storage/sqlite-store.js";
import { takeVaultCopy } from "./storage/vault-copy.js";
import { system32Path } from "./win32-paths.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    unlinkSync: vi.fn(actual.unlinkSync),
    realpathSync: vi.fn(actual.realpathSync),
  };
});

vi.mock("./storage/vault-copy.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./storage/vault-copy.js")>();
  return { ...actual, takeVaultCopy: vi.fn(actual.takeVaultCopy) };
});

vi.mock("./session/path-trust.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./session/path-trust.js")>();
  return {
    ...actual,
    assertOwnerOnlyDir: vi.fn(actual.assertOwnerOnlyDir),
    assertHeldDir: vi.fn(actual.assertHeldDir),
    isHeldPath: vi.fn(actual.isHeldPath),
  };
});

const realUnlink = (await vi.importActual<typeof import("node:fs")>("node:fs")).unlinkSync;
const realCopy = (
  await vi.importActual<typeof import("./storage/vault-copy.js")>("./storage/vault-copy.js")
).takeVaultCopy;
const realTrust =
  await vi.importActual<typeof import("./session/path-trust.js")>("./session/path-trust.js");

const win32 = process.platform === "win32";
const PASSWORD = "backup-password";
const LABEL = "--backup-dir";
const AT = new Date("2026-11-19T10:15:00.000Z");
const NAME = "harpoc-20261119T101500Z.db";
const LATER = new Date("2026-11-20T10:15:00.000Z");
const LATER_NAME = "harpoc-20261120T101500Z.db";
const OLDER = [
  "harpoc-20261116T101500Z.db",
  "harpoc-20261117T101500Z.db",
  "harpoc-20261118T101500Z.db",
];
const AHEAD = ["harpoc-20261120T101500Z.db", "harpoc-20261121T101500Z.db"];
const STALE = "harpoc-20261118T101500Z.db.0123456789ab.tmp";
const SIDES = ["-journal", "-wal", "-shm"];
const SCHEDULED = { trigger: "schedule", file: NAME };
const COMMAND = { trigger: "command", file: "vault-copy.db" };
const COPY_FAILURE = VaultError.databaseError("backup copy failed");
const USERS_SID = "S-1-5-32-545";
const NOT_CLOSED = "could not write the backup (the copy is not closed to other accounts)";

let dir: string;
let backups: string;
let dbPath: string;
let engine: VaultEngine;
const opened: VaultEngine[] = [];

beforeEach(async () => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-backup-")));
  backups = join(dir, "backups");
  mkdirSync(backups, { mode: 0o700 });
  dbPath = join(dir, "vault.db");
  engine = new VaultEngine({ dbPath, sessionPath: join(dir, "session.json") });
  await engine.initVault(PASSWORD);
});

afterEach(async () => {
  vi.mocked(takeVaultCopy).mockReset();
  vi.mocked(unlinkSync).mockReset();
  vi.mocked(realpathSync).mockReset();
  vi.mocked(assertOwnerOnlyDir).mockReset();
  vi.mocked(assertHeldDir).mockReset();
  vi.mocked(isHeldPath).mockReset();
  vi.restoreAllMocks();
  for (const other of opened.splice(0)) await other.destroy();
  await engine.destroy();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function scheduled(at: Date = AT, keep = 7): Promise<{ file: string }> {
  return engine.backupToDirectory(backups, { keep, label: LABEL, at });
}

function backupRows(reader: VaultEngine): Record<string, unknown>[] {
  return reader.queryAudit({ eventType: AuditEventType.VAULT_BACKUP }).map((row) => ({
    success: row.success,
    principal_type: row.principal_type,
    principal_id: row.principal_id,
    detail: row.detail,
  }));
}

function done(detail: Record<string, unknown>): Record<string, unknown> {
  return { success: true, principal_type: null, principal_id: null, detail };
}

function failed(detail: Record<string, unknown>, error: ErrorCode): Record<string, unknown> {
  return { success: false, principal_type: null, principal_id: null, detail: { ...detail, error } };
}

function readMeta(key: string): string | undefined {
  const store = new SqliteStore(dbPath);
  try {
    return store.getMeta(key);
  } finally {
    store.close();
  }
}

function liveStore(of: VaultEngine): SqliteStore {
  return (of as unknown as { store: SqliteStore }).store;
}

async function restored(copy: string): Promise<VaultEngine> {
  const fresh = join(dir, "restored");
  mkdirSync(fresh);
  copyFileSync(copy, join(fresh, "vault.db"));
  const second = new VaultEngine({
    dbPath: join(fresh, "vault.db"),
    sessionPath: join(fresh, "session.json"),
  });
  opened.push(second);
  await second.unlock(PASSWORD);
  return second;
}

function grantUsers(path: string, rights: string): void {
  const res = spawnSync(system32Path("icacls.exe"), [path, "/grant", `*${USERS_SID}:${rights}`], {
    shell: false,
    windowsHide: true,
  });
  expect(res.status).toBe(0);
}

/** Opens `path` to another account's read and answers the refusal `assertOwnerOnlyDir` then gives it under `label`. */
function unclose(path: string, label: string): string {
  if (win32) {
    grantUsers(path, "(OI)(CI)R");
    return `${label}: the access list grants ${USERS_SID} 0x00120089; only this process's account, SYSTEM and Administrators may hold a grant: ${path}`;
  }
  chmodSync(path, 0o750);
  return `${label}: mode 0750 is not 0700 (group- or world-accessible): ${path}`;
}

/** A directory another account can read, with the refusal `assertOwnerOnlyDir` gives it under `label`. */
function notClosed(label: string): { other: string; refusal: string } {
  const other = join(dir, "other");
  mkdirSync(other, { mode: 0o700 });
  return { other, refusal: unclose(other, label) };
}

/** A closed directory under `open`, a directory another account can change: 0777 off win32, a delete grant for Users on win32. */
function closedUnderOpen(): string {
  const open = join(dir, "open");
  mkdirSync(open);
  if (win32) grantUsers(open, "(D)");
  else chmodSync(open, 0o777);
  const closed = join(open, "backups");
  mkdirSync(closed, { mode: 0o700 });
  return closed;
}

function expectVaultAccountsAlone(acl: WindowsAclListing): void {
  expect([acl.user, SYSTEM_SID, ADMINISTRATORS_SID]).toContain(acl.owner);
  expect(new Set(acl.rules.map((rule) => rule.sid))).toEqual(
    new Set([acl.user, SYSTEM_SID, ADMINISTRATORS_SID]),
  );
  expect(acl.rules.every((rule) => rule.allow && !rule.inherited)).toBe(true);
}

async function attendedBesideCopies(): Promise<string> {
  const target = join(dir, "attended");
  mkdirSync(target);
  chmodSync(target, 0o755);
  for (const name of OLDER) writeFileSync(join(target, name), name);
  const file = join(target, "vault-copy.db");

  const result = await engine.backupToFile(file);

  expect(result).toEqual({ file });
  expect(backupRows(engine)).toEqual([done(COMMAND)]);
  expect(readdirSync(target).sort()).toEqual([...OLDER, "vault-copy.db"].sort());
  const second = await restored(file);
  expect(backupRows(second)).toEqual([done(COMMAND)]);
  expect(await second.unlockKeyStatus()).toEqual({ enrolled: false });
  return target;
}

describe("VaultEngine backups", () => {
  it("a scheduled backup writes its row first and the copy holds it", async () => {
    const { handle } = await engine.createSecret({
      name: "kept",
      type: "api_key",
      value: new Uint8Array(Buffer.from("kept-value")),
    });
    registerAgents(engine, "bot");
    const secretId = await engine.resolveSecretId(handle);
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "bot", permissions: ["read"] },
      "admin",
    );
    await engine.enrollUnlockKey();

    const { file } = await scheduled();

    expect(file).toBe(join(backups, NAME));
    expect(readdirSync(backups)).toEqual([NAME]);
    expect(backupRows(engine)).toEqual([done(SCHEDULED)]);
    const second = await restored(file);
    expect(second.listSecrets().map((info) => info.handle)).toEqual([handle]);
    expect(second.listPolicies()).toEqual(engine.listPolicies());
    expect(second.verifyAuditChain().valid).toBe(true);
    expect(backupRows(second)).toEqual([done(SCHEDULED)]);
    expect(await second.unlockKeyStatus()).toEqual({ enrolled: false });
  });

  it("a vault with an enrolled unlock key gives a copy without one", async () => {
    await engine.enrollUnlockKey();
    const slot = ["wrapped_kek_uk", "wrapped_kek_uk_iv", "wrapped_kek_uk_tag"].map(readMeta);

    const { file } = await scheduled();

    const bytes = readFileSync(file);
    expect(slot.every((value) => typeof value === "string" && value.length >= 16)).toBe(true);
    for (const value of slot) {
      expect(bytes.includes(Buffer.from(value as string))).toBe(false);
    }
  });

  // POSIX modes; the win32 arm reads the access list below.
  it.skipIf(win32)("no file of a run is ever wider than 0600", async () => {
    const seen: { mode: number; size: number }[] = [];
    vi.mocked(takeVaultCopy).mockImplementationOnce(async (request, options) => {
      const stat = statSync(request.tmpPath);
      seen.push({ mode: stat.mode & 0o777, size: stat.size });
      await realCopy(request, options);
    });

    const { file } = await scheduled();

    expect(seen).toEqual([{ mode: 0o600, size: 0 }]);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  // The win32 arm of the row above: an access list, not a mode.
  it.runIf(win32)(
    "on win32 the temporary file is closed to other accounts before the copy starts",
    async () => {
      const sizes: number[] = [];
      const lists: WindowsAclListing[] = [];
      vi.mocked(takeVaultCopy).mockImplementationOnce(async (request, options) => {
        sizes.push(statSync(request.tmpPath).size);
        lists.push(listWindowsAclSync(request.tmpPath));
        await realCopy(request, options);
      });

      await scheduled();

      expect(sizes).toEqual([0]);
      expect(lists).toHaveLength(1);
      expectVaultAccountsAlone(lists[0] as WindowsAclListing);
    },
  );

  // POSIX modes; on win32 the directory's access list is judged.
  it.skipIf(win32)("a directory that others can enter is refused after the row", async () => {
    chmodSync(backups, 0o750);

    const err = await expectVaultError(() => scheduled(), ErrorCode.INVALID_INPUT);

    expect(err.message).toBe(
      `${LABEL}: mode 0750 is not 0700 (group- or world-accessible): ${backups}`,
    );
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.INVALID_INPUT),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups)).toEqual([]);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  // POSIX modes; the win32 arm below grants a delete.
  it.skipIf(win32)(
    "a 0700 directory under a 0777 directory that is not sticky is refused at a run after the row",
    async () => {
      const closed = closedUnderOpen();

      const err = await expectVaultError(
        () => engine.backupToDirectory(closed, { keep: 7, label: LABEL, at: AT }),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(
        `${LABEL}: a directory on its path can be changed by another account: ${closed}`,
      );
      expect(backupRows(engine)).toEqual([
        failed(SCHEDULED, ErrorCode.INVALID_INPUT),
        done(SCHEDULED),
      ]);
      expect(readdirSync(closed)).toEqual([]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // The win32 arm of the row above: Users may delete the directory above the closed one.
  it.runIf(win32)(
    "on win32 a closed directory under a directory another account can delete is refused at a run after the row",
    async () => {
      const closed = closedUnderOpen();
      writeFileSync(join(closed, STALE), "stale");

      const err = await expectVaultError(
        () => engine.backupToDirectory(closed, { keep: 7, label: LABEL, at: AT }),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(
        `${LABEL}: a directory on its path can be changed by another account: ${closed}`,
      );
      expect(vi.mocked(assertOwnerOnlyDir).mock.calls).toEqual([[closed, LABEL]]);
      expect(backupRows(engine)).toEqual([
        failed(SCHEDULED, ErrorCode.INVALID_INPUT),
        done(SCHEDULED),
      ]);
      expect(readdirSync(closed)).toEqual([STALE]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // POSIX symbolic links: a link above the directory is followed before the walk.
  it.skipIf(win32)(
    "a directory reached through a link above it is judged and written at its real path",
    async () => {
      const real = join(dir, "real");
      mkdirSync(join(real, "backups"), { recursive: true, mode: 0o700 });
      const link = join(dir, "link");
      symlinkSync(real, link);

      const { file } = await engine.backupToDirectory(join(link, "backups"), {
        keep: 7,
        label: LABEL,
        at: AT,
      });

      expect(file).toBe(join(real, "backups", NAME));
      expect(readdirSync(join(real, "backups"))).toEqual([NAME]);
      expect(backupRows(engine)).toEqual([done(SCHEDULED)]);
    },
  );

  it("a directory that is not closed, under a directory another account can change, is refused with its own refusal at a run after the row", async () => {
    const shared = closedUnderOpen();
    const refusal = unclose(shared, LABEL);

    const err = await expectVaultError(
      () => engine.backupToDirectory(shared, { keep: 7, label: LABEL, at: AT }),
      ErrorCode.INVALID_INPUT,
    );

    expect(err.message).toBe(refusal);
    expect(vi.mocked(assertHeldDir).mock.invocationCallOrder[0] as number).toBeLessThan(
      vi.mocked(assertOwnerOnlyDir).mock.invocationCallOrder[0] as number,
    );
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.INVALID_INPUT),
      done(SCHEDULED),
    ]);
    expect(readdirSync(shared)).toEqual([]);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  // A junction needs no privilege on win32; off win32 the same call makes a symbolic link.
  it("a backup directory that is itself a link is refused at a run after the row, before the directories above it are judged", async () => {
    const link = join(dir, "link");
    symlinkSync(backups, link, "junction");

    const err = await expectVaultError(
      () => engine.backupToDirectory(link, { keep: 7, label: LABEL, at: AT }),
      ErrorCode.INVALID_INPUT,
    );

    expect(err.message).toBe(
      `${LABEL}: the path is a symbolic link or junction, not a directory: ${link}`,
    );
    expect(assertHeldDir).not.toHaveBeenCalled();
    expect(assertOwnerOnlyDir).not.toHaveBeenCalled();
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.INVALID_INPUT),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups)).toEqual([]);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  it("a run whose links lead, once the directories above are held, to a directory that is not closed is refused after the row", async () => {
    const { other, refusal } = notClosed(LABEL);
    vi.mocked(assertHeldDir).mockResolvedValueOnce(other);

    const err = await expectVaultError(() => scheduled(), ErrorCode.INVALID_INPUT);

    expect(err.message).toBe(refusal);
    expect(vi.mocked(assertOwnerOnlyDir).mock.calls).toEqual([[other, LABEL]]);
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.INVALID_INPUT),
      done(SCHEDULED),
    ]);
    expect(readdirSync(other)).toEqual([]);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  it("a directory that stops being closed while the directories above it are judged is refused after the row", async () => {
    let refusal = "";
    vi.mocked(assertHeldDir).mockImplementationOnce(async (path, label) => {
      const held = await realTrust.assertHeldDir(path, label);
      refusal = unclose(backups, LABEL);
      return held;
    });

    const err = await expectVaultError(() => scheduled(), ErrorCode.INVALID_INPUT);

    expect(err.message).toBe(refusal);
    expect(vi.mocked(assertOwnerOnlyDir).mock.calls).toEqual([[backups, LABEL]]);
    expect(vi.mocked(assertHeldDir).mock.invocationCallOrder[0] as number).toBeLessThan(
      vi.mocked(assertOwnerOnlyDir).mock.invocationCallOrder[0] as number,
    );
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.INVALID_INPUT),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups)).toEqual([]);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  it.runIf(win32)(
    "on win32 the copy's access list is the account, SYSTEM and Administrators",
    async () => {
      const { file } = await scheduled();

      expectVaultAccountsAlone(listWindowsAclSync(file));
    },
  );

  // POSIX modes; the win32 arm widens the access list.
  it.skipIf(win32)("a copy that others can read is refused at the read-back", async () => {
    vi.mocked(takeVaultCopy).mockImplementationOnce(async (request, options) => {
      await realCopy(request, options);
      chmodSync(request.tmpPath, 0o640);
    });

    const err = await expectVaultError(() => scheduled(), ErrorCode.FILE_IO_ERROR);

    expect(err.message).toBe(NOT_CLOSED);
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.FILE_IO_ERROR),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups)).toEqual([]);
  });

  it.runIf(win32)(
    "on win32 a copy whose access list grants another account is refused at the read-back",
    async () => {
      vi.mocked(takeVaultCopy).mockImplementationOnce(async (request, options) => {
        await realCopy(request, options);
        grantUsers(request.tmpPath, "R");
      });

      const err = await expectVaultError(() => scheduled(), ErrorCode.FILE_IO_ERROR);

      expect(err.message).toBe(NOT_CLOSED);
      expect(backupRows(engine)).toEqual([
        failed(SCHEDULED, ErrorCode.FILE_IO_ERROR),
        done(SCHEDULED),
      ]);
      expect(readdirSync(backups)).toEqual([]);
    },
  );

  it.each(SIDES)("a %s file left beside the copy fails the run and goes with it", async (side) => {
    vi.mocked(takeVaultCopy).mockImplementationOnce(async (request, options) => {
      await realCopy(request, options);
      writeFileSync(`${request.tmpPath}${side}`, "left");
    });

    const err = await expectVaultError(() => scheduled(), ErrorCode.FILE_IO_ERROR);

    expect(err.message).toBe(
      "could not write the backup (a journal file was left beside the copy)",
    );
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.FILE_IO_ERROR),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups)).toEqual([]);
  });

  it("a copy that fails beside its -journal, -wal and -shm files leaves none of them", async () => {
    vi.mocked(takeVaultCopy).mockImplementationOnce((request) => {
      for (const side of SIDES) writeFileSync(`${request.tmpPath}${side}`, "left");
      return Promise.reject(COPY_FAILURE);
    });

    const thrown = await expectVaultError(() => scheduled(), ErrorCode.DATABASE_ERROR);

    expect(thrown).toBe(COPY_FAILURE);
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.DATABASE_ERROR),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups)).toEqual([]);
  });

  it("a sealed vault writes nothing", async () => {
    const attended = join(dir, "attended.db");
    await engine.lock();

    await expectVaultError(() => scheduled(), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => scheduled(AT, 0), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => scheduled(new Date(Number.NaN)), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.backupToFile(attended), ErrorCode.VAULT_LOCKED);
    await expectVaultError(() => engine.backupToFile("attended.db"), ErrorCode.VAULT_LOCKED);

    await engine.unlock(PASSWORD);
    expect(backupRows(engine)).toEqual([]);
    expect(readdirSync(backups)).toEqual([]);
    expect(existsSync(attended)).toBe(false);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  it("a copy that fails leaves a failed row and no file", async () => {
    const failure = VaultError.databaseError("backup check failed");
    vi.mocked(takeVaultCopy).mockImplementationOnce(async (request, options) => {
      await realCopy({ ...request, slotKeys: [] }, options);
      throw failure;
    });

    const thrown = await expectVaultError(() => scheduled(), ErrorCode.DATABASE_ERROR);

    expect(thrown).toBe(failure);
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.DATABASE_ERROR),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups)).toEqual([]);
  });

  it("a failed row that cannot be written changes nothing else", async () => {
    vi.mocked(takeVaultCopy).mockImplementationOnce(() => {
      vi.spyOn(liveStore(engine), "insertAuditEvent").mockImplementationOnce(() => {
        throw new Error("injected write failure");
      });
      return Promise.reject(COPY_FAILURE);
    });

    const thrown = await expectVaultError(() => scheduled(), ErrorCode.DATABASE_ERROR);

    expect(thrown).toBe(COPY_FAILURE);
    expect(backupRows(engine)).toEqual([done(SCHEDULED)]);
    expect(readdirSync(backups)).toEqual([]);
  });

  it("a temporary file that cannot be removed leaves the first error and its failed row, and the next run removes it", async () => {
    vi.mocked(takeVaultCopy).mockImplementationOnce(() => Promise.reject(COPY_FAILURE));
    let held = false;
    vi.mocked(unlinkSync).mockImplementation((path) => {
      if (!held && String(path).endsWith(".tmp")) {
        held = true;
        throw Object.assign(new Error("held"), { code: "EBUSY" });
      }
      realUnlink(path);
    });

    const thrown = await expectVaultError(() => scheduled(), ErrorCode.DATABASE_ERROR);

    expect(thrown).toBe(COPY_FAILURE);
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.DATABASE_ERROR),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups).filter(isBackupTempName)).toHaveLength(1);

    await scheduled(LATER);

    expect(readdirSync(backups)).toEqual([LATER_NAME]);
  });

  it("a final name that exists is never overwritten", async () => {
    const { file } = await scheduled();
    const first = readFileSync(file);

    const err = await expectVaultError(() => scheduled(), ErrorCode.FILE_IO_ERROR);

    expect(err.message).toBe("could not write the backup (EEXIST)");
    expect(readFileSync(file).equals(first)).toBe(true);
    expect(readdirSync(backups)).toEqual([NAME]);
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.FILE_IO_ERROR),
      done(SCHEDULED),
      done(SCHEDULED),
    ]);
  });

  it("the oldest copies beyond keep are removed and nothing else", async () => {
    for (const name of [...OLDER, "notes.txt", "harpoc-x.db"]) {
      writeFileSync(join(backups, name), name);
    }

    await scheduled(AT, 2);

    expect(readdirSync(backups).sort()).toEqual(
      [OLDER[2] as string, NAME, "harpoc-x.db", "notes.txt"].sort(),
    );
    expect(backupRows(engine)).toEqual([done(SCHEDULED)]);
  });

  it("a copy that vanished is not an error", async () => {
    for (const name of OLDER) writeFileSync(join(backups, name), name);
    const vanished = join(backups, OLDER[0] as string);
    vi.mocked(unlinkSync).mockImplementation((path) => {
      if (path === vanished) realUnlink(path);
      realUnlink(path);
    });

    await scheduled(AT, 3);

    expect(readdirSync(backups).sort()).toEqual([OLDER[1] as string, OLDER[2] as string, NAME]);
    expect(backupRows(engine)).toEqual([done(SCHEDULED)]);
  });

  it("a fresh copy older by its stamp than the copies beside it is kept", async () => {
    for (const name of AHEAD) writeFileSync(join(backups, name), name);

    const { file } = await scheduled(AT, AHEAD.length);

    expect(file).toBe(join(backups, NAME));
    expect(readdirSync(backups).sort()).toEqual([NAME, AHEAD[1] as string]);
    expect(backupRows(engine)).toEqual([done(SCHEDULED)]);
  });

  it("keep of 0, a fraction or NaN is refused with no row", async () => {
    for (const name of OLDER) writeFileSync(join(backups, name), name);

    for (const keep of [0, 1.5, Number.NaN, -1, Number.POSITIVE_INFINITY]) {
      const err = await expectVaultError(() => scheduled(AT, keep), ErrorCode.INVALID_INPUT);
      expect(err.message, String(keep)).toBe("backup: keep must be a whole number of at least 1");
    }

    expect(backupRows(engine)).toEqual([]);
    expect(readdirSync(backups).sort()).toEqual(OLDER);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  it("a time that is no valid date, or whose year a copy's name cannot hold, is refused with no row", async () => {
    for (const at of [
      new Date(Number.NaN),
      new Date("+010000-01-01T00:00:00.000Z"),
      new Date("0099-12-31T23:59:59.000Z"),
    ]) {
      const err = await expectVaultError(() => scheduled(at), ErrorCode.INVALID_INPUT);
      expect(err.message, String(at.getTime())).toBe("backup: the time is not a valid date");
    }

    expect(backupRows(engine)).toEqual([]);
    expect(readdirSync(backups)).toEqual([]);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  it("a stale temporary file is removed by the next run", async () => {
    writeFileSync(join(backups, `${OLDER[2] as string}.0123456789ab.tmp`), "stale");

    await scheduled();

    expect(readdirSync(backups)).toEqual([NAME]);
  });

  it("an abort ends the run", async () => {
    const controller = new AbortController();
    vi.mocked(takeVaultCopy).mockImplementationOnce((request, options) => {
      const copy = realCopy(request, options);
      controller.abort();
      return copy;
    });

    const err = await expectVaultError(
      () =>
        engine.backupToDirectory(backups, {
          keep: 7,
          label: LABEL,
          at: AT,
          signal: controller.signal,
        }),
      ErrorCode.DATABASE_ERROR,
    );

    expect(err.message).toBe("Database error: backup did not finish");
    expect(vi.mocked(takeVaultCopy).mock.calls[0]?.[1]?.signal).toBe(controller.signal);
    expect(backupRows(engine)).toEqual([
      failed(SCHEDULED, ErrorCode.DATABASE_ERROR),
      done(SCHEDULED),
    ]);
    expect(readdirSync(backups).filter(isBackupTempName)).toEqual([]);
    expect(readdirSync(backups)).toEqual([]);
  });
});

describe("VaultEngine attended backups", () => {
  // Off win32 the exclusive 0600 create closes the file by itself; the win32 arm below judges.
  it.skipIf(win32)(
    "writes a command row and prunes nothing, with no owner-only judgement of its directory",
    async () => {
      await attendedBesideCopies();

      expect(assertOwnerOnlyDir).not.toHaveBeenCalled();
    },
  );

  // On win32 a file is born with its directory's inheritable entries, so the directory is judged.
  it.runIf(win32)(
    "on win32 writes a command row, judges the target's directory and prunes nothing",
    async () => {
      const target = await attendedBesideCopies();

      expect(vi.mocked(assertOwnerOnlyDir).mock.calls).toEqual([[target, "backup"]]);
    },
  );

  it("an abort ends an attended run: the temporary file is removed and the failed row written", async () => {
    const target = join(dir, "attended");
    mkdirSync(target);
    chmodSync(target, 0o755);
    const controller = new AbortController();
    vi.mocked(takeVaultCopy).mockImplementationOnce((request, options) => {
      const copy = realCopy(request, options);
      controller.abort();
      return copy;
    });

    const err = await expectVaultError(
      () => engine.backupToFile(join(target, "vault-copy.db"), { signal: controller.signal }),
      ErrorCode.DATABASE_ERROR,
    );

    expect(err.message).toBe("Database error: backup did not finish");
    expect(vi.mocked(takeVaultCopy).mock.calls[0]?.[1]?.signal).toBe(controller.signal);
    expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.DATABASE_ERROR), done(COMMAND)]);
    expect(readdirSync(target).filter(isBackupTempName)).toEqual([]);
    expect(readdirSync(target)).toEqual([]);
  });

  // The read grant is an access-list entry; off win32 the walk of the path judges write access.
  it.runIf(win32)(
    "on win32 an attended backup into a directory another account can read is refused after the row",
    async () => {
      const target = join(dir, "shared");
      mkdirSync(target);
      writeFileSync(join(target, STALE), "stale");
      grantUsers(target, "(OI)(CI)R");
      const file = join(target, "vault-copy.db");

      const err = await expectVaultError(() => engine.backupToFile(file), ErrorCode.INVALID_INPUT);

      expect(err.message).toBe(
        `backup: the access list grants ${USERS_SID} 0x00120089; only this process's account, SYSTEM and Administrators may hold a grant: ${target}`,
      );
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(target)).toEqual([STALE]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // On win32 the access list of the target's directory passes, and Users may delete the directory above it.
  it.runIf(win32)(
    "on win32 an attended backup into a closed directory under a directory another account can delete is refused after the row",
    async () => {
      const target = closedUnderOpen();
      writeFileSync(join(target, STALE), "stale");
      const file = join(target, "vault-copy.db");

      const err = await expectVaultError(() => engine.backupToFile(file), ErrorCode.INVALID_INPUT);

      expect(err.message).toBe(
        "backup: a directory on the target's path can be changed by another account",
      );
      expect(vi.mocked(assertOwnerOnlyDir).mock.calls).toEqual([[target, "backup"]]);
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(target)).toEqual([STALE]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // On win32 the access list of the target's directory refuses first where the directories above it are not held either.
  it.runIf(win32)(
    "on win32 an attended backup into a directory that is not closed, under a directory another account can delete, is refused with the directory's own refusal after the row",
    async () => {
      const target = closedUnderOpen();
      const refusal = unclose(target, "backup");

      const err = await expectVaultError(
        () => engine.backupToFile(join(target, "vault-copy.db")),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(refusal);
      expect(vi.mocked(isHeldPath).mock.invocationCallOrder[0] as number).toBeLessThan(
        vi.mocked(assertOwnerOnlyDir).mock.invocationCallOrder[0] as number,
      );
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(target)).toEqual([]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // A junction needs no privilege, and only win32 refuses a link as the target's directory itself.
  it.runIf(win32)(
    "on win32 an attended backup whose directory is itself a junction is refused after the row, before the directories above it are judged",
    async () => {
      const real = join(dir, "attended");
      mkdirSync(real);
      const link = join(dir, "link");
      symlinkSync(real, link, "junction");

      const err = await expectVaultError(
        () => engine.backupToFile(join(link, "vault-copy.db")),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(
        `backup: the path is a symbolic link or junction, not a directory: ${link}`,
      );
      expect(isHeldPath).not.toHaveBeenCalled();
      expect(assertOwnerOnlyDir).not.toHaveBeenCalled();
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(real)).toEqual([]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // On win32 the target's directory is judged closed where its links lead.
  it.runIf(win32)(
    "on win32 an attended backup whose links lead, once the directories above are held, to a directory that is not closed is refused after the row",
    async () => {
      const target = join(dir, "attended");
      mkdirSync(target);
      const { other, refusal } = notClosed("backup");
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      vi.mocked(realpathSync).mockImplementation(((path: string) =>
        path === target ? other : actual.realpathSync(path)) as typeof realpathSync);

      const err = await expectVaultError(
        () => engine.backupToFile(join(target, "vault-copy.db")),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(refusal);
      expect(vi.mocked(assertOwnerOnlyDir).mock.calls).toEqual([[other, "backup"]]);
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(other)).toEqual([]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // On win32 the target's directory is judged closed once the directories above it are held, not before.
  it.runIf(win32)(
    "on win32 an attended backup into a directory that stops being closed while the directories above it are judged is refused after the row",
    async () => {
      const target = join(dir, "attended");
      mkdirSync(target);
      let refusal = "";
      vi.mocked(isHeldPath).mockImplementationOnce(async (file) => {
        const held = await realTrust.isHeldPath(file);
        refusal = unclose(target, "backup");
        return held;
      });

      const err = await expectVaultError(
        () => engine.backupToFile(join(target, "vault-copy.db")),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(refusal);
      expect(vi.mocked(assertOwnerOnlyDir).mock.calls).toEqual([[target, "backup"]]);
      expect(vi.mocked(isHeldPath).mock.invocationCallOrder[0] as number).toBeLessThan(
        vi.mocked(assertOwnerOnlyDir).mock.invocationCallOrder[0] as number,
      );
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(target)).toEqual([]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // POSIX modes: another account that can write the directory can replace the run's temporary file; win32 judges its access list above.
  it.skipIf(win32)(
    "an attended backup into a directory another account can write is refused after the row",
    async () => {
      const target = join(dir, "shared");
      mkdirSync(target);
      writeFileSync(join(target, STALE), "stale");
      chmodSync(target, 0o777);
      const file = join(target, "vault-copy.db");

      const err = await expectVaultError(() => engine.backupToFile(file), ErrorCode.INVALID_INPUT);

      expect(err.message).toBe(
        "backup: a directory on the target's path can be changed by another account",
      );
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(target)).toEqual([STALE]);
      expect(existsSync(file)).toBe(false);
      expect(takeVaultCopy).not.toHaveBeenCalled();

      chmodSync(target, 0o755);

      expect(await engine.backupToFile(file)).toEqual({ file });
      expect(readdirSync(target)).toEqual(["vault-copy.db"]);
      expect(backupRows(engine)).toEqual([
        done(COMMAND),
        failed(COMMAND, ErrorCode.INVALID_INPUT),
        done(COMMAND),
      ]);
    },
  );

  // POSIX symbolic links: win32 refuses a link or junction as the target's directory itself.
  it.skipIf(win32)(
    "an attended backup through a link is written into the directory the link names",
    async () => {
      const real = join(dir, "real");
      mkdirSync(real);
      chmodSync(real, 0o755);
      const link = join(dir, "link");
      symlinkSync(real, link);

      const result = await engine.backupToFile(join(link, "vault-copy.db"));

      expect(result).toEqual({ file: join(real, "vault-copy.db") });
      expect(readdirSync(real)).toEqual(["vault-copy.db"]);
      expect(backupRows(engine)).toEqual([done(COMMAND)]);
    },
  );

  // POSIX symbolic links and modes, as the row above.
  it.skipIf(win32)(
    "an attended backup through a link into a directory another account can write is refused",
    async () => {
      const shared = join(dir, "shared");
      mkdirSync(shared);
      chmodSync(shared, 0o777);
      const link = join(dir, "link");
      symlinkSync(shared, link);

      const err = await expectVaultError(
        () => engine.backupToFile(join(link, "vault-copy.db")),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(
        "backup: a directory on the target's path can be changed by another account",
      );
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(readdirSync(shared)).toEqual([]);
      expect(takeVaultCopy).not.toHaveBeenCalled();
    },
  );

  // POSIX: off win32 the target's directory is resolved before the walk; the win32 arm judges it as typed.
  it.skipIf(win32)("a target whose parent is a regular file keeps its file error", async () => {
    const plain = join(dir, "plain");
    writeFileSync(plain, "");

    const err = await expectVaultError(
      () => engine.backupToFile(join(plain, "vault-copy.db")),
      ErrorCode.FILE_IO_ERROR,
    );

    expect(err.message).toBe("could not write the backup (ENOTDIR)");
    expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.FILE_IO_ERROR), done(COMMAND)]);
    expect(readFileSync(plain, "utf8")).toBe("");
  });

  it("refuses a target that is not an absolute path, with no row", async () => {
    for (const file of ["", "vault-copy.db", join("attended", "vault-copy.db")]) {
      const err = await expectVaultError(() => engine.backupToFile(file), ErrorCode.INVALID_INPUT);
      expect(err.message, file).toBe("backup: the target is not an absolute path");
    }

    expect(backupRows(engine)).toEqual([]);
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  it("refuses a file that exists, with no row", async () => {
    const file = join(dir, "taken.db");
    writeFileSync(file, "taken");

    const err = await expectVaultError(() => engine.backupToFile(file), ErrorCode.INVALID_INPUT);

    expect(err.message).toBe(`backup: ${file} exists; a backup is written to a new file only`);
    expect(backupRows(engine)).toEqual([]);
    expect(readFileSync(file, "utf8")).toBe("taken");
    expect(takeVaultCopy).not.toHaveBeenCalled();
  });

  // Off win32 a directory that does not exist keeps the file system's answer; the win32 arm is below.
  it.skipIf(win32)("a directory that does not exist fails after the row", async () => {
    const file = join(dir, "missing", "copy.db");

    const err = await expectVaultError(() => engine.backupToFile(file), ErrorCode.FILE_IO_ERROR);

    expect(err.message).toBe("could not write the backup (ENOENT)");
    const command = { trigger: "command", file: "copy.db" };
    expect(backupRows(engine)).toEqual([failed(command, ErrorCode.FILE_IO_ERROR), done(command)]);
    expect(existsSync(join(dir, "missing"))).toBe(false);
  });

  // On win32 the judgement of the target's directory comes before the create and refuses first.
  it.runIf(win32)(
    "on win32 a directory that does not exist is refused by the judgement after the row",
    async () => {
      const missing = join(dir, "missing");

      const err = await expectVaultError(
        () => engine.backupToFile(join(missing, "vault-copy.db")),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(`backup: no such directory: ${missing}`);
      expect(backupRows(engine)).toEqual([failed(COMMAND, ErrorCode.INVALID_INPUT), done(COMMAND)]);
      expect(existsSync(missing)).toBe(false);
    },
  );
});
