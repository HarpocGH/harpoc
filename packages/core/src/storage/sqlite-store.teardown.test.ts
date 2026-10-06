import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SqliteStore } from "./sqlite-store.js";

function removeTempDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

describe("teardown removal of a store's directory (X-1)", () => {
  it.runIf(process.platform === "win32")(
    "throws while the store still holds its database open",
    () => {
      const dir = mkdtempSync(join(tmpdir(), "harpoc-teardown-"));
      const store = new SqliteStore(join(dir, "held.vault.db"));
      try {
        store.setMeta("k", "v");
        expect(() => removeTempDir(dir)).toThrow(/EBUSY|ENOTEMPTY|EPERM/);
        expect(existsSync(dir)).toBe(true);
      } finally {
        store.close();
        removeTempDir(dir);
      }
    },
  );

  it("removes the directory once the store is closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "harpoc-teardown-"));
    const store = new SqliteStore(join(dir, "closed.vault.db"));
    store.setMeta("k", "v");
    store.close();
    removeTempDir(dir);
    expect(existsSync(dir)).toBe(false);
  });
});
