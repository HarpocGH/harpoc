import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  rmdirSync,
  statSync,
  utimesSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionFile } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, mkdirSync: vi.fn(actual.mkdirSync), statSync: vi.fn(actual.statSync) };
});

// Captured before any vi.useFakeTimers(): the real-clock case below must be
// able to poll while the fake clock stands still, and vi.waitFor cannot serve
// — it advances fake timers between its own polls, which would drive the very
// setTimeout the product must be proven not to use.
const realSetTimeout: typeof setTimeout = setTimeout;
const realDateNow: typeof Date.now = Date.now;

async function waitOnRealClock(done: () => boolean, budgetMs = 5_000): Promise<void> {
  const deadline = realDateNow() + budgetMs;
  while (!done() && realDateNow() < deadline) {
    await new Promise<void>((resolve) => realSetTimeout(resolve, 10));
  }
}

function ioError(code: string): NodeJS.ErrnoException {
  const err = new Error(`${code}: injected`) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

let tempDir: string;
let sessionPath: string;
let lockPath: string;

// Unlike the slide and wipe suites, these cases read the written file back
// through sessionFileSchema, so every wrapped-key placeholder must be base64.
const b64 = (text: string): string => Buffer.from(text).toString("base64");

const sessionExpiringSoon = (): SessionFile =>
  SessionManager.createSessionData(
    "01890000-0000-7000-8000-000000000000",
    "vault-1",
    Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
    b64("a"),
    b64("b"),
    b64("c"),
    b64("d"),
    b64("e"),
    b64("f"),
    b64("g"),
    b64("h"),
    b64("i"),
    5_000, // live, but far enough from a 60 s slide to exceed the 1 s write threshold
  );

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "harpoc-lock-"));
  sessionPath = join(tempDir, "session.json");
  lockPath = `${sessionPath}.lock`;
});

afterEach(() => {
  vi.mocked(mkdirSync).mockReset();
  vi.mocked(statSync).mockReset();
  rmSync(tempDir, { recursive: true, force: true });
});

describe("session.json.lock (R8/D56)", () => {
  it("a held lock makes the slide skip: nothing written, the stored file returned unchanged", async () => {
    const manager = new SessionManager(sessionPath);
    await manager.writeSession(sessionExpiringSoon());
    const before = readFileSync(sessionPath, "utf8");
    mkdirSync(lockPath);

    const result = await manager.extendSession(60_000, true);

    expect(result).toEqual(JSON.parse(before));
    expect(readFileSync(sessionPath, "utf8")).toBe(before);
    expect(existsSync(lockPath)).toBe(true);
  });

  it("a stale lock is reclaimed: the slide writes and releases", async () => {
    const manager = new SessionManager(sessionPath, { lockStaleMs: 200 });
    await manager.writeSession(sessionExpiringSoon());
    const before = JSON.parse(readFileSync(sessionPath, "utf8")) as SessionFile;
    mkdirSync(lockPath);
    const stale = new Date(Date.now() - 1_000);
    utimesSync(lockPath, stale, stale);

    const result = await manager.extendSession(60_000, true);

    expect(result?.expires_at).toBeGreaterThan(before.expires_at);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("a fresh held lock makes the erase wait for the stale bound, then proceed", async () => {
    const manager = new SessionManager(sessionPath, { lockStaleMs: 200 });
    await manager.writeSession(sessionExpiringSoon());
    mkdirSync(lockPath);
    const started = Date.now();

    await manager.eraseSession();

    expect(Date.now() - started).toBeGreaterThanOrEqual(200);
    expect(existsSync(sessionPath)).toBe(false);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("the fresh write waits too: the file lands once the lock is released", async () => {
    const manager = new SessionManager(sessionPath, { lockStaleMs: 5_000 });
    mkdirSync(lockPath);

    const write = manager.writeSession(sessionExpiringSoon());
    await sleep(100);
    expect(existsSync(sessionPath)).toBe(false);

    rmdirSync(lockPath);
    await write;

    expect(existsSync(sessionPath)).toBe(true);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("every path releases the lock", async () => {
    const manager = new SessionManager(sessionPath);
    await manager.writeSession(sessionExpiringSoon());
    expect(existsSync(lockPath)).toBe(false);
    await manager.extendSession(60_000, true);
    expect(existsSync(lockPath)).toBe(false);
    await manager.eraseSession();
    expect(readdirSync(tempDir)).toEqual([]);
  });

  it("the wait poll runs on the real clock: an erase settles under fake timers (R31)", async () => {
    const manager = new SessionManager(sessionPath, { lockStaleMs: 200 });
    await manager.writeSession(sessionExpiringSoon());
    mkdirSync(lockPath);
    const started = realDateNow();
    vi.useFakeTimers();
    try {
      const settled = { done: false };
      const erase = manager.eraseSession().then(() => {
        settled.done = true;
      });

      await waitOnRealClock(() => settled.done);

      expect(settled.done).toBe(true);
      await erase;
      expect(realDateNow() - started).toBeGreaterThanOrEqual(200);
      expect(existsSync(sessionPath)).toBe(false);
      // The foreign lock is never reclaimed: isLockStale keeps the fakeable
      // clock (D7 captures the real one for the poll only), so the erase takes
      // the documented proceed-unlocked path out of the bounded wait.
      expect(existsSync(lockPath)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a non-EEXIST mkdir errno proceeds unlocked and is reported through the seam (R30)", async () => {
    const failures: Error[] = [];
    const manager = new SessionManager(sessionPath, {
      lockStaleMs: 50,
      onPermissionRepairFailure: (err) => failures.push(err),
    });
    await manager.writeSession(sessionExpiringSoon());
    vi.mocked(mkdirSync).mockImplementation(() => {
      throw ioError("EACCES");
    });

    await manager.eraseSession();

    expect(existsSync(sessionPath)).toBe(false);
    expect(existsSync(lockPath)).toBe(false);
    const lockFailures = failures.filter((err) => err.message.includes("EACCES"));
    expect(lockFailures).toHaveLength(1);
    expect(lockFailures[0]?.message).toContain("session lock");
  });

  it("a lock released between the mkdir and the stat is acquired on the retry (R30)", async () => {
    const manager = new SessionManager(sessionPath, { lockStaleMs: 5_000 });
    await manager.writeSession(sessionExpiringSoon());
    const before = JSON.parse(readFileSync(sessionPath, "utf8")) as SessionFile;
    mkdirSync(lockPath);
    // The holder releases exactly between our mkdir and our stat.
    vi.mocked(statSync).mockImplementationOnce((target) => {
      rmdirSync(target);
      throw ioError("ENOENT");
    });

    const result = await manager.extendSession(60_000, true);

    expect(result?.expires_at).toBeGreaterThan(before.expires_at);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("a contended slide over a missing session file writes nothing and reports no session", async () => {
    const manager = new SessionManager(sessionPath, { lockStaleMs: 200 });
    mkdirSync(lockPath);

    const result = await manager.extendSession(60_000, true);

    expect(result).toBeNull();
    expect(existsSync(sessionPath)).toBe(false);
    expect(existsSync(lockPath)).toBe(true);
  });
});
