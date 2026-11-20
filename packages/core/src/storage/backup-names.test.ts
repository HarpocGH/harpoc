import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  backupFileName,
  backupSideNames,
  freeBackupTime,
  isBackupTempName,
  newestBackupAt,
  parseBackupFileName,
  pruneBackups,
  removeBackupTemps,
} from "./backup-names.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, unlinkSync: vi.fn(actual.unlinkSync) };
});

const realUnlink = (await vi.importActual<typeof import("node:fs")>("node:fs")).unlinkSync;

const AT = Date.UTC(2026, 10, 19, 10, 15, 0);
const NAME = "harpoc-20261119T101500Z.db";
const TEMP = `${NAME}.0123456789ab.tmp`;
const OLDER = "harpoc-20261118T101500Z.db";
const OLDEST = "harpoc-20261117T101500Z.db";
const NEWEST = "harpoc-20261120T000001Z.db";
const SIDES = ["-journal", "-wal", "-shm"];

let dir: string;

beforeEach(() => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-backup-names-")));
});

afterEach(() => {
  vi.mocked(unlinkSync).mockReset();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function place(...names: string[]): void {
  for (const name of names) writeFileSync(join(dir, name), name);
}

describe("backup names", () => {
  it("a name round-trips", () => {
    expect(backupFileName(new Date(AT))).toBe(NAME);
    expect(backupFileName(new Date(AT + 999))).toBe(NAME);
    expect(parseBackupFileName(NAME)).toBe(AT);
    expect(parseBackupFileName(backupFileName(new Date(Date.UTC(2027, 0, 2, 3, 4, 5))))).toBe(
      Date.UTC(2027, 0, 2, 3, 4, 5),
    );
  });

  it("harpoc-x.db, a copy's name with .tmp after it, a 13-digit date and vault.db are no copies", () => {
    for (const name of [
      "harpoc-x.db",
      `${NAME}.tmp`,
      "harpoc-2026111T101500Z.db",
      "harpoc-20261119T10150Z.db",
      "vault.db",
      TEMP,
      `${NAME} `,
      `x${NAME}`,
      ...SIDES.map((side) => `${NAME}${side}`),
      ...SIDES.map((side) => `${TEMP}${side}`),
    ]) {
      expect(parseBackupFileName(name), name).toBeNull();
    }
  });

  it("a stamp that is no date of the calendar is no copy", () => {
    for (const name of [
      "harpoc-20261319T101500Z.db",
      "harpoc-20260230T101500Z.db",
      "harpoc-20261119T241500Z.db",
      "harpoc-20261119T106000Z.db",
      "harpoc-00501119T101500Z.db",
    ]) {
      expect(parseBackupFileName(name), name).toBeNull();
    }
  });

  it("newestBackupAt answers the newest copy's stamp and ignores every other name", () => {
    place(OLDER, NAME, NEWEST, "harpoc-x.db", "vault.db", "notes.txt", TEMP);
    place("harpoc-20991231T000000Z.db.0123456789ab.tmp", "harpoc-20991231T000000Z.db.tmp");
    place("harpoc-20991331T000000Z.db");

    expect(newestBackupAt(dir)).toBe(Date.UTC(2026, 10, 20, 0, 0, 1));
  });

  it("newestBackupAt with a bound ignores a later stamp and answers the newest one at or before it", () => {
    place(OLDER, NAME, NEWEST);

    expect(newestBackupAt(dir, AT)).toBe(AT);
    expect(newestBackupAt(dir, AT - 1)).toBe(Date.UTC(2026, 10, 18, 10, 15, 0));
    expect(newestBackupAt(dir, Date.UTC(2026, 10, 20, 0, 0, 1))).toBe(
      Date.UTC(2026, 10, 20, 0, 0, 1),
    );
  });

  it("newestBackupAt answers null for a bound older than every stamp", () => {
    place(OLDER, NAME);

    expect(newestBackupAt(dir, Date.UTC(2026, 10, 18, 10, 14, 59))).toBeNull();
  });

  it("newestBackupAt answers null for an empty directory and for one without a copy", () => {
    expect(newestBackupAt(dir)).toBeNull();

    place("harpoc-x.db", TEMP, "notes.txt");

    expect(newestBackupAt(dir)).toBeNull();
  });

  it("freeBackupTime answers the second of the time where no entry holds its copy's name", () => {
    expect(freeBackupTime(dir, new Date(AT + 999))).toEqual(new Date(AT));

    place(OLDER, "notes.txt");

    expect(freeBackupTime(dir, new Date(AT))).toEqual(new Date(AT));
  });

  it("freeBackupTime passes the seconds whose copy's name is taken", () => {
    place(NAME);
    expect(freeBackupTime(dir, new Date(AT))).toEqual(new Date(AT + 1_000));

    place(backupFileName(new Date(AT + 1_000)), backupFileName(new Date(AT + 2_000)));
    expect(freeBackupTime(dir, new Date(AT))).toEqual(new Date(AT + 3_000));
  });

  it("freeBackupTime counts no side file or temporary file of a second as its copy", () => {
    place(TEMP, ...SIDES.map((side) => `${NAME}${side}`));

    expect(freeBackupTime(dir, new Date(AT))).toEqual(new Date(AT));
  });

  it("freeBackupTime answers the sixtieth second where sixty are taken", () => {
    for (let second = 0; second < 60; second++) {
      place(backupFileName(new Date(AT + second * 1_000)));
    }

    expect(freeBackupTime(dir, new Date(AT))).toEqual(new Date(AT + 59_000));
  });

  it("isBackupTempName accepts a copy's name, 12 lower-case hex digits and .tmp, with -journal, -wal or -shm after it or without, nothing else", () => {
    expect(isBackupTempName(TEMP)).toBe(true);
    expect(isBackupTempName(`${OLDER}.fedcba987654.tmp`)).toBe(true);
    for (const side of SIDES) {
      expect(isBackupTempName(`${TEMP}${side}`), side).toBe(true);
    }
    for (const name of [
      NAME,
      `${NAME}.tmp`,
      `${NAME}.0123456789AB.tmp`,
      `${NAME}.0123456789a.tmp`,
      `${NAME}.0123456789abc.tmp`,
      `${NAME}.0123456789ag.tmp`,
      `${NAME}-journal`,
      `${TEMP}-journals`,
      `${TEMP}-wal-shm`,
      `${TEMP}-`,
      `${TEMP}.wal`,
      `${NAME}.0123456789ab-journal`,
      `${TEMP}.tmp`,
      `x${TEMP}`,
      "notes.txt.0123456789ab.tmp",
      "vault.db.0123456789ab.tmp",
      "harpoc-x.db.0123456789ab.tmp",
      "harpoc-20261319T101500Z.db.0123456789ab.tmp",
      "harpoc-20261319T101500Z.db.0123456789ab.tmp-journal",
    ]) {
      expect(isBackupTempName(name), name).toBe(false);
    }
  });

  it("backupSideNames answers a file's -journal, -wal and -shm names", () => {
    expect(backupSideNames(join(dir, TEMP)).sort()).toEqual(
      SIDES.map((side) => join(dir, `${TEMP}${side}`)).sort(),
    );
  });

  it("removeBackupTemps removes the temporary names, their -journal, -wal and -shm names, and nothing else", () => {
    const second = `${OLDER}.fedcba987654.tmp`;
    const orphan = `${NEWEST}.00000000beef.tmp-journal`;
    const sides = SIDES.map((side) => `${TEMP}${side}`);
    const resembling = [
      "notes.txt.0123456789ab.tmp",
      `${NAME}.ABCDEF012345.tmp`,
      `${NAME}-journal`,
      `${TEMP}-journals`,
      "harpoc-20261319T101500Z.db.0123456789ab.tmp",
    ];
    place(TEMP, second, orphan, NAME, "notes.txt", ...sides, ...resembling);
    mkdirSync(join(dir, "nested"));
    writeFileSync(join(dir, "nested", TEMP), "nested");

    removeBackupTemps(dir);

    expect(readdirSync(dir).sort()).toEqual([NAME, "nested", "notes.txt", ...resembling].sort());
    expect(readdirSync(join(dir, "nested"))).toEqual([TEMP]);
  });

  it("removeBackupTemps takes a name that vanished between the listing and its removal as removed", () => {
    const vanished = join(dir, TEMP);
    const second = `${OLDER}.fedcba987654.tmp`;
    place(TEMP, second, NAME);
    vi.mocked(unlinkSync).mockImplementation((path) => {
      if (path === vanished) realUnlink(path);
      realUnlink(path);
    });

    removeBackupTemps(dir);

    expect(readdirSync(dir)).toEqual([NAME]);
  });

  it("removeBackupTemps throws any other failure", () => {
    place(TEMP);
    const denied = Object.assign(new Error("denied"), { code: "EACCES" });
    vi.mocked(unlinkSync).mockImplementationOnce(() => {
      throw denied;
    });

    let thrown: unknown;
    try {
      removeBackupTemps(dir);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBe(denied);
    expect(readdirSync(dir)).toEqual([TEMP]);
  });

  it("pruneBackups removes the oldest copies beyond keep and nothing else", () => {
    const others = ["notes.txt", "harpoc-x.db", "vault.db", TEMP, `${TEMP}-journal`];
    const beside = [`${OLDEST}-journal`, `${OLDEST}.tmp`, "harpoc-20261319T101500Z.db"];
    place(OLDEST, OLDER, NAME, NEWEST, ...others, ...beside);

    pruneBackups(dir, 3, NEWEST);

    expect(readdirSync(dir).sort()).toEqual([OLDER, NAME, NEWEST, ...others, ...beside].sort());
  });

  it("pruneBackups never removes the fresh copy, whatever its stamp", () => {
    place(OLDEST, OLDER, NAME, NEWEST, "notes.txt");

    pruneBackups(dir, 2, OLDEST);

    expect(readdirSync(dir).sort()).toEqual([OLDEST, NEWEST, "notes.txt"].sort());
  });

  it("pruneBackups with keep 1 leaves the fresh copy alone among the copies", () => {
    place(OLDEST, OLDER, NAME, NEWEST, "notes.txt");

    pruneBackups(dir, 1, OLDER);

    expect(readdirSync(dir).sort()).toEqual([OLDER, "notes.txt"].sort());
  });

  it("pruneBackups removes nothing while the copies are within keep", () => {
    place(OLDEST, OLDER, NAME);

    pruneBackups(dir, 3, NAME);

    expect(readdirSync(dir).sort()).toEqual([OLDEST, OLDER, NAME].sort());
  });

  it("pruneBackups takes a copy that vanished between the listing and its removal as removed", () => {
    const vanished = join(dir, OLDEST);
    place(OLDEST, OLDER, NAME, NEWEST);
    vi.mocked(unlinkSync).mockImplementation((path) => {
      if (path === vanished) realUnlink(path);
      realUnlink(path);
    });

    pruneBackups(dir, 2, NEWEST);

    expect(readdirSync(dir).sort()).toEqual([NAME, NEWEST].sort());
  });

  it("pruneBackups throws any other failure", () => {
    place(OLDER, NAME);
    const denied = Object.assign(new Error("denied"), { code: "EACCES" });
    vi.mocked(unlinkSync).mockImplementationOnce(() => {
      throw denied;
    });

    let thrown: unknown;
    try {
      pruneBackups(dir, 1, NAME);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBe(denied);
    expect(readdirSync(dir).sort()).toEqual([OLDER, NAME].sort());
  });
});
