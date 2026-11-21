import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { DaemonPaths } from "./local-path.js";
import { holdsProtectedPath } from "./local-path.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    realpath: vi.fn(actual.realpath),
    lstat: vi.fn(actual.lstat),
    stat: vi.fn(actual.stat),
  };
});

let root: string;
let vault: string;
let vaultFiles: string[];

beforeAll(() => {
  // `.native` like the product's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-holds-protected-")));
  vault = join(root, "vault");
  for (const dir of [join(vault, "inner"), join(root, "vau"), join(root, "sibling")]) {
    mkdirSync(dir, { recursive: true });
  }
  for (const dir of [join(root, "agent", "keys"), join(root, "other")]) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(join(vault, "vault.db"), "");
  writeFileSync(join(vault, "session.json"), "");
  writeFileSync(join(root, "agent", "token"), "");
  writeFileSync(join(root, "other", "token"), "");
  vaultFiles = [join(vault, "vault.db"), join(vault, "session.json")];
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function declared(paths: Partial<DaemonPaths>): DaemonPaths {
  return { protectedDirs: [], protectedFiles: [], ...paths };
}

describe("holdsProtectedPath", () => {
  it("a directory that holds the vault's directory, and that directory itself, answer true", async () => {
    expect(await holdsProtectedPath(root, vaultFiles)).toBe(true);
    expect(await holdsProtectedPath(vault, vaultFiles)).toBe(true);
  });

  it.each([
    ["a directory inside the vault's directory", () => join(vault, "inner")],
    ["a sibling of the vault's directory", () => join(root, "sibling")],
    ["a directory whose name the vault's begins with", () => join(root, "vau")],
  ])("%s answers false", async (_label, dir) => {
    expect(await holdsProtectedPath(dir(), vaultFiles)).toBe(false);
  });

  it.each([
    [
      "a declared directory inside",
      () => declared({ protectedDirs: [join(root, "agent", "keys")] }),
    ],
    ["a declared file inside", () => declared({ protectedFiles: [join(root, "agent", "token")] })],
  ])("%s answers true", async (_label, daemon) => {
    expect(await holdsProtectedPath(join(root, "agent"), vaultFiles, daemon())).toBe(true);
  });

  it("a declared file outside answers false", async () => {
    expect(
      await holdsProtectedPath(
        join(root, "agent"),
        vaultFiles,
        declared({ protectedFiles: [join(root, "other", "token")] }),
      ),
    ).toBe(false);
  });

  it.each([
    [
      "a declared file",
      () => declared({ protectedFiles: [join(root, "agent", "missing", "token")] }),
    ],
    ["a declared directory", () => declared({ protectedDirs: [join(root, "agent", "missing")] })],
  ])("%s inside that does not exist yet answers true", async (_label, daemon) => {
    expect(await holdsProtectedPath(join(root, "agent"), vaultFiles, daemon())).toBe(true);
  });

  it("a vault directory whose realpath fails EACCES answers true", async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    const denied = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    vi.mocked(realpath).mockImplementation(async (path, options) => {
      if (path === vault) throw denied;
      return actual.realpath(path, options);
    });
    try {
      expect(await holdsProtectedPath(join(root, "sibling"), vaultFiles)).toBe(true);
    } finally {
      vi.mocked(realpath).mockImplementation(actual.realpath);
    }
  });
});
