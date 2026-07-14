import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionFile } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";

let tempDir: string;
let sessionPath: string;

const sessionExpiringNow = (): SessionFile =>
  SessionManager.createSessionData(
    "01890000-0000-7000-8000-000000000000",
    "vault-1",
    Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    0, // expires immediately, so a slide's extension exceeds the 1s write threshold
  );

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "harpoc-slide-"));
  sessionPath = join(tempDir, "session.json");
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(tempDir, { recursive: true, force: true });
});

describe("extendSession slide/lock resurrection guard", () => {
  it("does not resurrect an erased session file when requireExisting is set", async () => {
    const manager = new SessionManager(sessionPath, {});
    // Pretend the file existed at read time (a concurrent lock erases it before
    // the rename); the file is absent on disk.
    vi.spyOn(manager, "readStoredSession").mockResolvedValue(sessionExpiringNow());

    const result = await manager.extendSession(60_000, true);

    expect(result).toBeNull();
    expect(existsSync(sessionPath)).toBe(false);
  });

  it("recreates the file without requireExisting (negative control)", async () => {
    const manager = new SessionManager(sessionPath, {});
    vi.spyOn(manager, "readStoredSession").mockResolvedValue(sessionExpiringNow());

    const result = await manager.extendSession(60_000, false);

    expect(result).not.toBeNull();
    expect(existsSync(sessionPath)).toBe(true);
  });
});
