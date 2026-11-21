import { once } from "node:events";
import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { Worker } from "node:worker_threads";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import * as vaultCopy from "./vault-copy.js";
import { VAULT_COPY_WORKER_SOURCE, takeVaultCopy } from "./vault-copy.js";

const started = vi.hoisted(
  () => [] as { threadId: number; execArgv: readonly string[] | undefined; exited: boolean }[],
);
const silent = vi.hoisted(() => ({ next: false, worker: undefined as Worker | undefined }));

vi.mock("node:worker_threads", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:worker_threads")>();
  class TrackedWorker extends actual.Worker {
    constructor(...args: ConstructorParameters<typeof actual.Worker>) {
      const exitsWithoutAnswer = silent.next;
      silent.next = false;
      super(...(exitsWithoutAnswer ? (["", args[1]] as typeof args) : args));
      if (exitsWithoutAnswer) silent.worker = this;
      const record = { threadId: this.threadId, execArgv: args[1]?.execArgv, exited: false };
      started.push(record);
      this.once("exit", () => {
        record.exited = true;
      });
    }
  }
  return { ...actual, Worker: TrackedWorker };
});

const WRAPPED_KEK_MARKER = "wrapped-kek-uk-marker-".padEnd(64, "k");
const WRAPPED_KEK_IV_MARKER = "wrapped-kek-uk-iv-marker-".padEnd(64, "i");
const WRAPPED_KEK_TAG_MARKER = "wrapped-kek-uk-tag-marker-".padEnd(64, "t");
const ENROLLED_AT_MARKER = "unlock-key-enrolled-at-marker-".padEnd(64, "e");

const SLOT: readonly (readonly [string, string])[] = [
  ["wrapped_kek_uk", WRAPPED_KEK_MARKER],
  ["wrapped_kek_uk_iv", WRAPPED_KEK_IV_MARKER],
  ["wrapped_kek_uk_tag", WRAPPED_KEK_TAG_MARKER],
  ["unlock_key_enrolled_at", ENROLLED_AT_MARKER],
];
const SLOT_KEYS = SLOT.map(([key]) => key);
const OTHER_META: readonly (readonly [string, string])[] = [
  ["schema_version", "13"],
  ["failed_attempts", "0"],
  ["lockout_until", "0"],
];
const ROW_BODY = "r".repeat(200);
const LARGE_SOURCE_MEGABYTES = 64;
const DAY_MS = 24 * 60 * 60 * 1_000;
const DRIVER = createRequire(import.meta.url).resolve("better-sqlite3");

let dir: string;
let dbPath: string;
let tmpPath: string;
let source: Database.Database;

beforeEach(() => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-vault-copy-")));
  dbPath = join(dir, "vault.db");
  tmpPath = join(dir, "harpoc-20261119T120000Z.db.0123456789ab.tmp");
  source = new Database(dbPath);
  source.pragma("journal_mode = WAL");
  source.exec(
    "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;" +
      "CREATE TABLE rows (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT;",
  );
  const meta = source.prepare("INSERT INTO vault_meta (key, value) VALUES (?, ?)");
  for (const [key, value] of [...SLOT, ...OTHER_META]) meta.run(key, value);
  const row = source.prepare("INSERT INTO rows (body) VALUES (?)");
  source.transaction(() => {
    for (let i = 0; i < 2_000; i += 1) row.run(ROW_BODY);
  })();
  closeSync(openSync(tmpPath, "wx", 0o600));
});

afterEach(() => {
  vi.useRealTimers();
  source.close();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function request(): { dbPath: string; tmpPath: string; slotKeys: readonly string[] } {
  return { dbPath, tmpPath, slotKeys: SLOT_KEYS };
}

function readCopy<T>(path: string, read: (db: Database.Database) => T): T {
  const db = new Database(path, { readonly: true, fileMustExist: true });
  try {
    return read(db);
  } finally {
    db.close();
  }
}

function metaKeys(db: Database.Database): string[] {
  return (db.prepare("SELECT key FROM vault_meta ORDER BY key").all() as { key: string }[]).map(
    (row) => row.key,
  );
}

function metaValue(db: Database.Database, key: string): string | undefined {
  return (
    db.prepare("SELECT value FROM vault_meta WHERE key = ?").get(key) as
      { value: string } | undefined
  )?.value;
}

function rowCount(db: Database.Database): number {
  return (db.prepare("SELECT count(*) AS n FROM rows").get() as { n: number }).n;
}

function liveThreadIds(): number[] {
  return started.filter((worker) => !worker.exited).map((worker) => worker.threadId);
}

function largeSource(): string {
  const path = join(dir, "large.db");
  const db = new Database(path);
  db.pragma("synchronous = OFF");
  db.exec(
    "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;" +
      "CREATE TABLE filler (id INTEGER PRIMARY KEY, body BLOB NOT NULL) STRICT;",
  );
  const fill = db.prepare("INSERT INTO filler (body) VALUES (zeroblob(1048576))");
  db.transaction(() => {
    for (let i = 0; i < LARGE_SOURCE_MEGABYTES; i += 1) fill.run();
  })();
  db.close();
  return path;
}

async function untilNotEmptyOrSettled(
  path: string,
  ending: Promise<"resolved" | "rejected">,
  signal: AbortSignal,
): Promise<void> {
  let ended: "resolved" | "rejected" | undefined;
  while (ended === undefined && statSync(path).size === 0) {
    signal.throwIfAborted();
    ended = await Promise.race([
      ending,
      new Promise<undefined>((resolve) => setImmediate(resolve, undefined)),
    ]);
  }
}

async function whileWriting(writer: Database.Database, run: () => Promise<void>): Promise<void> {
  const insert = writer.prepare("INSERT INTO rows (body) VALUES (?)");
  let writing = true;
  const tick = (): void => {
    if (!writing) return;
    insert.run(ROW_BODY);
    setImmediate(tick);
  };
  setImmediate(tick);
  try {
    await run();
  } finally {
    writing = false;
  }
}

function journalRefusingDriver(): string {
  const path = join(dir, "journal-refusing-driver.cjs");
  writeFileSync(
    path,
    [
      `const Database = require(${JSON.stringify(DRIVER)});`,
      "module.exports = class extends Database {",
      "  pragma(source, options) {",
      '    return source.startsWith("journal_mode") ? "delete" : super.pragma(source, options);',
      "  }",
      "};",
    ].join("\n"),
  );
  return path;
}

describe("takeVaultCopy", () => {
  it("the copy opens, passes its check and holds no slot", async () => {
    await takeVaultCopy(request());

    const bytes = readFileSync(tmpPath);
    expect(bytes.includes(Buffer.from(WRAPPED_KEK_MARKER))).toBe(false);
    expect(bytes.includes(Buffer.from(WRAPPED_KEK_IV_MARKER))).toBe(false);
    expect(bytes.includes(Buffer.from(WRAPPED_KEK_TAG_MARKER))).toBe(false);
    expect(bytes.includes(Buffer.from(ENROLLED_AT_MARKER))).toBe(false);
    expect([bytes[18], bytes[19]]).toEqual([1, 1]);
    expect(readdirSync(dir).filter((name) => name.startsWith(basename(tmpPath)))).toEqual([
      basename(tmpPath),
    ]);
    readCopy(tmpPath, (copy) => {
      expect(metaKeys(copy)).toEqual(["failed_attempts", "lockout_until", "schema_version"]);
      expect(copy.pragma("integrity_check", { simple: true })).toBe("ok");
      expect(rowCount(copy)).toBe(2_000);
    });
  });

  it("the source is untouched", async () => {
    await takeVaultCopy(request());

    for (const [key, value] of SLOT) {
      expect(metaValue(source, key) === value).toBe(true);
    }
  });

  it("a copy taken while the source connection writes finishes and is a snapshot", async () => {
    const atStart = rowCount(source);

    await whileWriting(source, () => takeVaultCopy(request()));

    const atEnd = rowCount(source);
    const copied = readCopy(tmpPath, rowCount);
    expect(atEnd).toBeGreaterThan(atStart);
    expect(copied).toBeGreaterThanOrEqual(atStart);
    expect(copied).toBeLessThanOrEqual(atEnd);
  });

  it("a copy taken while a second connection writes finishes", async () => {
    const second = new Database(dbPath);
    try {
      const atStart = rowCount(second);

      await whileWriting(second, () => takeVaultCopy(request()));

      expect(rowCount(second)).toBeGreaterThan(atStart);
      expect(readCopy(tmpPath, (copy) => copy.pragma("integrity_check", { simple: true }))).toBe(
        "ok",
      );
    } finally {
      second.close();
    }
  });

  it("a temporary file that is not empty is refused", async () => {
    const earlier = new Database(tmpPath);
    earlier.exec("CREATE TABLE earlier (id INTEGER PRIMARY KEY)");
    earlier.close();
    const before = readFileSync(tmpPath);

    const err = await expectVaultError(() => takeVaultCopy(request()), ErrorCode.DATABASE_ERROR);

    expect(err.message).toBe("Database error: backup copy failed");
    expect(readFileSync(tmpPath).equals(before)).toBe(true);
  });

  it("a temporary file that is missing is refused", async () => {
    unlinkSync(tmpPath);

    const err = await expectVaultError(() => takeVaultCopy(request()), ErrorCode.DATABASE_ERROR);

    expect(err.message).toBe("Database error: backup copy failed");
    expect(existsSync(tmpPath)).toBe(false);
  });

  it("a source that is missing is refused", async () => {
    const missing = join(dir, "missing.db");

    const err = await expectVaultError(
      () => takeVaultCopy({ dbPath: missing, tmpPath, slotKeys: SLOT_KEYS }),
      ErrorCode.DATABASE_ERROR,
    );

    expect(err.message).toBe("Database error: backup copy failed");
    expect(existsSync(missing)).toBe(false);
  });

  it("a source without a vault_meta table is refused at the strip", async () => {
    const bare = join(dir, "bare.db");
    const db = new Database(bare);
    db.exec("CREATE TABLE rows (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT");
    db.close();

    const err = await expectVaultError(
      () => takeVaultCopy({ dbPath: bare, tmpPath, slotKeys: SLOT_KEYS }),
      ErrorCode.DATABASE_ERROR,
    );

    expect(err.message).toBe("Database error: backup strip failed");
  });

  it("a copy that fails its integrity check is refused", async () => {
    source.exec("CREATE TABLE checked (n INTEGER NOT NULL CHECK (n > 0)) STRICT");
    source.pragma("ignore_check_constraints = ON");
    source.prepare("INSERT INTO checked (n) VALUES (?)").run(-1);
    source.pragma("ignore_check_constraints = OFF");

    const err = await expectVaultError(() => takeVaultCopy(request()), ErrorCode.DATABASE_ERROR);

    expect(err.message).toBe("Database error: backup check failed");
  });

  it("a copy whose journal_mode=MEMORY is not taken is refused at the strip", async () => {
    const worker = new Worker(VAULT_COPY_WORKER_SOURCE, {
      eval: true,
      workerData: { driver: journalRefusingDriver(), dbPath, tmpPath, slotKeys: SLOT_KEYS },
    });
    const exited = once(worker, "exit");

    const [answer] = (await once(worker, "message")) as [unknown];
    await exited;

    expect(answer).toBe("strip");
    expect(readCopy(tmpPath, metaKeys)).toHaveLength(SLOT.length + OTHER_META.length);
  });

  it("an abort ends the worker", async () => {
    const before = started.length;
    const controller = new AbortController();

    const copy = takeVaultCopy(request(), { signal: controller.signal });
    controller.abort();
    const err = await expectVaultError(() => copy, ErrorCode.DATABASE_ERROR);

    expect(err.message).toBe("Database error: backup did not finish");
    expect(started.length).toBe(before + 1);
    expect(liveThreadIds()).toEqual([]);
  });

  it("once a copy has settled after an abort, its file is free and no worker is left", async ({
    signal,
  }) => {
    const large = largeSource();
    const controller = new AbortController();

    const copy = takeVaultCopy(
      { dbPath: large, tmpPath, slotKeys: SLOT_KEYS },
      { signal: controller.signal },
    );
    const ending = copy.then(
      () => "resolved" as const,
      () => "rejected" as const,
    );
    await untilNotEmptyOrSettled(tmpPath, ending, signal);
    controller.abort();
    const ended = await ending;
    unlinkSync(tmpPath);

    expect(liveThreadIds()).toEqual([]);
    if (ended === "rejected") {
      const err = await expectVaultError(() => copy, ErrorCode.DATABASE_ERROR);
      expect(err.message).toBe("Database error: backup did not finish");
    }
  });

  it("no clock ends a copy", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const before = started.length;

    const copy = takeVaultCopy(request());
    const armed = vi.getTimerCount();
    vi.advanceTimersByTime(DAY_MS);
    await copy;

    expect(armed).toBe(0);
    expect(readCopy(tmpPath, (db) => db.pragma("integrity_check", { simple: true }))).toBe("ok");
    expect(started.length).toBe(before + 1);
    expect(liveThreadIds()).toEqual([]);
    expect("VAULT_COPY_TIMEOUT_MS" in vaultCopy).toBe(false);
  });

  it("a worker that exits without an answer rejects as not finished", async () => {
    silent.next = true;
    let outcome: "pending" | "resolved" | "rejected" = "pending";

    const copy = takeVaultCopy(request());
    void copy.then(
      () => (outcome = "resolved"),
      () => (outcome = "rejected"),
    );
    await once(silent.worker as Worker, "exit");
    await new Promise<void>((resolve) => setImmediate(resolve));

    expect(outcome).toBe("rejected");
    const err = await expectVaultError(() => copy, ErrorCode.DATABASE_ERROR);
    expect(err.message).toBe("Database error: backup did not finish");
    expect(readFileSync(tmpPath).length).toBe(0);
    expect(liveThreadIds()).toEqual([]);
  });

  it("the worker is started with an empty execArgv", async () => {
    await takeVaultCopy(request());

    expect(started.at(-1)?.execArgv).toEqual([]);
  });

  it("the worker's source holds no placeholder and no backslash", () => {
    expect(VAULT_COPY_WORKER_SOURCE.includes("${")).toBe(false);
    expect(VAULT_COPY_WORKER_SOURCE.includes("\\")).toBe(false);
  });
});
