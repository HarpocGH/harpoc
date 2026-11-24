import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, sep } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { writeHelperFiles } from "./spawn-captured-helpers.js";
import type { HelperFiles, HelperFilesSpec } from "./spawn-captured-helpers.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    mkdtempSync: vi.fn(actual.mkdtempSync),
    rmSync: vi.fn(actual.rmSync),
    writeFileSync: vi.fn(actual.writeFileSync),
  };
});

const { writeFileSync: realWriteFileSync } =
  await vi.importActual<typeof import("node:fs")>("node:fs");

const win32 = process.platform === "win32";

const SPEC: HelperFilesSpec = {
  prefix: "harpoc-helper-test-",
  script: "helper.mjs",
  launcher: { posix: "helper.sh", win32: "helper.cmd" },
  source: 'process.stdout.write("ran");\n',
};
const LAUNCHER = win32 ? SPEC.launcher.win32 : SPEC.launcher.posix;
const ECHO_SOURCE =
  'import { readFileSync } from "node:fs"; process.stdout.write(JSON.stringify([process.argv.slice(2), readFileSync(0, "utf8")]));';

function overrideTempEnv(dir: string): { TMPDIR?: string; TMP?: string; TEMP?: string } {
  const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = dir;
  process.env.TMP = dir;
  process.env.TEMP = dir;
  return saved;
}

function restoreTempEnv(saved: { TMPDIR?: string; TMP?: string; TEMP?: string }): void {
  if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = saved.TMPDIR;
  if (saved.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = saved.TMP;
  if (saved.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = saved.TEMP;
}

function identity(err: unknown): unknown {
  return err;
}

function expectScriptAndPrefix(files: HelperFiles): void {
  expect(readFileSync(join(files.dir, SPEC.script), "utf8")).toBe(SPEC.source);
  expect(basename(files.dir).startsWith(SPEC.prefix)).toBe(true);
}

let tempRoot: string;
let saved: { TMPDIR?: string; TMP?: string; TEMP?: string };

beforeEach(() => {
  tempRoot = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-helpers-")));
  saved = overrideTempEnv(tempRoot);
});

afterEach(() => {
  restoreTempEnv(saved);
  vi.mocked(writeFileSync).mockReset();
  vi.mocked(mkdtempSync).mockReset();
  vi.mocked(rmSync).mockReset();
  rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("writeHelperFiles", () => {
  it.runIf(!win32)("the POSIX launcher, letter for letter", () => {
    const plain = writeHelperFiles(SPEC, identity);
    const quiet = writeHelperFiles({ ...SPEC, nullStdin: true }, identity);
    expect(plain.launcher).toBe(join(plain.dir, SPEC.launcher.posix));
    expect(readFileSync(plain.launcher, "utf8")).toBe(
      `#!/bin/sh\nexec '${process.execPath}' '${join(plain.dir, SPEC.script)}' "$@"\n`,
    );
    expect(quiet.launcher).toBe(join(quiet.dir, SPEC.launcher.posix));
    expect(readFileSync(quiet.launcher, "utf8")).toBe(
      `#!/bin/sh\nexec '${process.execPath}' '${join(quiet.dir, SPEC.script)}' "$@" </dev/null\n`,
    );
    for (const files of [plain, quiet]) {
      expect(statSync(join(files.dir, SPEC.script)).mode & 0o777).toBe(0o700);
      expect(statSync(files.launcher).mode & 0o777).toBe(0o700);
      expect(statSync(files.dir).mode & 0o777).toBe(0o700);
      expectScriptAndPrefix(files);
    }
  });

  it.runIf(win32)("the win32 launcher, letter for letter", () => {
    const plain = writeHelperFiles(SPEC, identity);
    const quiet = writeHelperFiles({ ...SPEC, nullStdin: true }, identity);
    expect(plain.launcher).toBe(join(plain.dir, SPEC.launcher.win32));
    expect(readFileSync(plain.launcher, "utf8")).toBe(
      `@"${process.execPath}" "${join(plain.dir, SPEC.script)}" %*\r\n`,
    );
    expect(quiet.launcher).toBe(join(quiet.dir, SPEC.launcher.win32));
    expect(readFileSync(quiet.launcher, "utf8")).toBe(
      `@"${process.execPath}" "${join(quiet.dir, SPEC.script)}" %* <NUL\r\n`,
    );
    for (const files of [plain, quiet]) expectScriptAndPrefix(files);
  });

  // Off win32 only: node refuses to spawn a .cmd file without a shell.
  it.runIf(!win32)("the launcher hands its arguments on and, where asked, the null device", () => {
    const spec = { ...SPEC, source: ECHO_SOURCE };
    const run = (files: HelperFiles) =>
      spawnSync(files.launcher, ["a b", "c"], { input: "line\n", encoding: "utf8" });
    const plain = run(writeHelperFiles(spec, identity));
    const quiet = run(writeHelperFiles({ ...spec, nullStdin: true }, identity));
    expect(plain.stdout).toBe(JSON.stringify([["a b", "c"], "line\n"]));
    expect(plain.status).toBe(0);
    expect(quiet.stdout).toBe(JSON.stringify([["a b", "c"], ""]));
    expect(quiet.status).toBe(0);
  });

  // Off win32 only: node refuses to spawn a .cmd file without a shell.
  it.runIf(!win32)("a temporary directory whose path holds a blank", () => {
    const blank = join(tempRoot, "a blank");
    mkdirSync(blank);
    overrideTempEnv(blank);
    const files = writeHelperFiles(
      { ...SPEC, source: 'process.stdout.write(process.argv[2] ?? "");\n' },
      identity,
    );
    expect(files.dir.startsWith(blank + sep)).toBe(true);
    const r = spawnSync(files.launcher, ["an argument"], { encoding: "utf8" });
    expect(r.stdout).toBe("an argument");
    expect(r.status).toBe(0);
  });

  // Off win32 only: node refuses to spawn a .cmd file without a shell.
  it.runIf(!win32)("a temporary directory whose path holds a `$`", () => {
    const dollar = join(tempRoot, "a$HOME b");
    mkdirSync(dollar);
    overrideTempEnv(dollar);
    const files = writeHelperFiles(
      { ...SPEC, source: 'process.stdout.write(process.argv[2] ?? "");\n' },
      identity,
    );
    expect(files.dir.startsWith(dollar + sep)).toBe(true);
    const r = spawnSync(files.launcher, ["an argument"], { encoding: "utf8" });
    expect(r.stdout).toBe("an argument");
    expect(r.status).toBe(0);
  });

  // Off win32 only: node refuses to spawn a .cmd file without a shell.
  it.runIf(!win32)('a temporary directory whose path holds a quote, a backquote and a `"`', () => {
    const quoted = join(tempRoot, "a'b`c\"d");
    mkdirSync(quoted);
    overrideTempEnv(quoted);
    const files = writeHelperFiles(
      { ...SPEC, source: 'process.stdout.write(process.argv[2] ?? "");\n' },
      identity,
    );
    expect(files.dir.startsWith(quoted + sep)).toBe(true);
    const r = spawnSync(files.launcher, ["an argument"], { encoding: "utf8" });
    expect(r.stdout).toBe("an argument");
    expect(r.status).toBe(0);
  });

  it("a directory that cannot be made leaves as the mapping's error", () => {
    const raw = new Error("mkdtemp injected");
    const mapped = new Error("mapped");
    vi.mocked(mkdtempSync).mockImplementationOnce(() => {
      throw raw;
    });
    const failure = vi.fn<(err: unknown) => unknown>(() => mapped);
    let thrown: unknown;
    try {
      writeHelperFiles(SPEC, failure);
    } catch (err) {
      thrown = err;
    }
    expect(failure.mock.calls.length).toBe(1);
    expect(failure.mock.calls[0]?.[0]).toBe(raw);
    expect(thrown).toBe(mapped);
    expect(readdirSync(tempRoot)).toEqual([]);
  });

  describe("a write that fails removes the directory and leaves as the mapping's error", () => {
    function expectWriteFailure(failing: string, written: string[]): void {
      const raw = new Error("write injected");
      const mapped = new Error("mapped");
      vi.mocked(writeFileSync).mockImplementation((file, data, options) => {
        if (basename(String(file)) === failing) throw raw;
        realWriteFileSync(file, data, options);
      });
      const failure = vi.fn<(err: unknown) => unknown>(() => mapped);
      let thrown: unknown;
      try {
        writeHelperFiles(SPEC, failure);
      } catch (err) {
        thrown = err;
      }
      expect(vi.mocked(writeFileSync).mock.calls.map(([file]) => basename(String(file)))).toEqual(
        written,
      );
      expect(failure.mock.calls.length).toBe(1);
      expect(failure.mock.calls[0]?.[0]).toBe(raw);
      expect(thrown).toBe(mapped);
      expect(readdirSync(tempRoot)).toEqual([]);
    }

    it("the script's write", () => {
      expectWriteFailure(SPEC.script, [SPEC.script]);
    });

    it("the launcher's write", () => {
      expectWriteFailure(LAUNCHER, [SPEC.script, LAUNCHER]);
    });
  });

  it("dispose removes the directory and survives a second call", () => {
    const files = writeHelperFiles(SPEC, identity);
    expect(existsSync(files.dir)).toBe(true);
    files.dispose();
    expect(existsSync(files.dir)).toBe(false);
    vi.mocked(rmSync).mockImplementationOnce(() => {
      throw new Error("rm injected");
    });
    expect(() => files.dispose()).not.toThrow();
  });
});
