import { chmodSync, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { SqliteStore } from "./sqlite-store.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, chmodSync: vi.fn(actual.chmodSync) };
});

let dir: string;
let store: SqliteStore | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-dbmode-"));
});

afterEach(() => {
  store?.close();
  store = undefined;
  vi.mocked(chmodSync).mockReset();
  rmSync(dir, { recursive: true, force: true });
});

describe("database file mode at creation (D55)", () => {
  it.runIf(process.platform !== "win32")(
    "is 0600 on disk even when the trailing chmod is a no-op",
    () => {
      vi.mocked(chmodSync).mockImplementation(() => undefined);
      const previous = process.umask(0o022);
      try {
        const dbPath = join(dir, "modes.vault.db");
        store = new SqliteStore(dbPath);
        expect(statSync(dbPath).mode & 0o777).toBe(0o600);
      } finally {
        process.umask(previous);
      }
    },
  );

  it("does not create a file for an in-memory store", () => {
    store = new SqliteStore(":memory:");
    expect(existsSync(":memory:")).toBe(false);
  });

  // R5: the empty path is not the in-memory sentinel — the 0600 pre-create
  // opens `""`, which is ENOENT, and the store refuses. Pinned so the refusal
  // cannot quietly become SQLite's anonymous on-disk temporary database.
  it("refuses an empty path as a database error", async () => {
    await expectVaultError(() => new SqliteStore(""), ErrorCode.DATABASE_ERROR);
  });
});
