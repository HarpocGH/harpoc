import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  rmdirSync,
  utimesSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SessionFile } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";

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
});
