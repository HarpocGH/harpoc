import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import {
  assertConsumerDir,
  assertRuntimeDir,
  consumerDir,
  isPrivateDirMode,
  resolveRuntimeDir,
} from "./runtime-dir.js";
import { expectVaultError } from "@harpoc/test-utils";

const FLAG_AS_PATH =
  "--runtime-dir: a flag, not a path (give a path that starts with a dash as ./-name)";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-runtime-dir-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("resolveRuntimeDir", () => {
  it("the --runtime-dir option wins over $RUNTIME_DIRECTORY", () => {
    expect(resolveRuntimeDir("/srv/harpoc-run", { RUNTIME_DIRECTORY: "/run/harpoc" })).toEqual({
      path: "/srv/harpoc-run",
      source: "--runtime-dir",
    });
  });

  it("falls back to $RUNTIME_DIRECTORY without the option", () => {
    expect(resolveRuntimeDir(undefined, { RUNTIME_DIRECTORY: "/run/harpoc" })).toEqual({
      path: "/run/harpoc",
      source: "$RUNTIME_DIRECTORY",
    });
  });

  it.each([{}, { RUNTIME_DIRECTORY: "" }])(
    "resolves nothing without the option and without the variable (%j)",
    (env) => {
      expect(resolveRuntimeDir(undefined, env)).toBeUndefined();
    },
  );

  // systemd.exec(5), RuntimeDirectory=: several directories reach the variable
  // joined with ":" — nothing says which one is the runtime directory.
  it("refuses a $RUNTIME_DIRECTORY that lists several directories", async () => {
    const err = await expectVaultError(
      () => resolveRuntimeDir(undefined, { RUNTIME_DIRECTORY: "/run/harpoc:/run/other" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      "$RUNTIME_DIRECTORY: several directories (/run/harpoc:/run/other); name one with --runtime-dir",
    );
  });

  it.each(["", "  "])("refuses an empty --runtime-dir (%j) as INVALID_INPUT", async (value) => {
    const err = await expectVaultError(() => resolveRuntimeDir(value, {}), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe("--runtime-dir: empty path");
  });

  it.each(["--rest", "-x", "-"])(
    "refuses a flag Commander took as the --runtime-dir path (%j) as INVALID_INPUT",
    async (value) => {
      const err = await expectVaultError(
        () => resolveRuntimeDir(value, {}),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(FLAG_AS_PATH);
    },
  );

  it("accepts a dash-led path written as ./-name", () => {
    expect(resolveRuntimeDir("./-run", {})).toEqual({ path: "./-run", source: "--runtime-dir" });
  });
});

describe("isPrivateDirMode", () => {
  it.each([
    { mode: 0o700, octal: "0700" },
    { mode: 0o750, octal: "0750" },
    { mode: 0o40750, octal: "40750 (a directory's type bits)" },
    { mode: 0o42750, octal: "42750 (setgid)" },
  ])("accepts mode $octal", ({ mode }) => {
    expect(isPrivateDirMode(mode)).toBe(true);
  });

  it.each([
    { mode: 0o770, octal: "0770 (group write)" },
    { mode: 0o755, octal: "0755 (world read and search)" },
    { mode: 0o751, octal: "0751 (world search)" },
    { mode: 0o720, octal: "0720 (group write alone)" },
  ])("refuses mode $octal", ({ mode }) => {
    expect(isPrivateDirMode(mode)).toBe(false);
  });
});

describe("assertRuntimeDir", () => {
  it("refuses a missing path, naming the option", async () => {
    const missing = join(dir, "missing");
    const err = await expectVaultError(
      () => assertRuntimeDir({ path: missing, source: "--runtime-dir" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(`--runtime-dir: no such directory: ${missing}`);
  });

  it("names $RUNTIME_DIRECTORY when the directory came from the environment", async () => {
    const missing = join(dir, "missing");
    const err = await expectVaultError(
      () => assertRuntimeDir({ path: missing, source: "$RUNTIME_DIRECTORY" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(`$RUNTIME_DIRECTORY: no such directory: ${missing}`);
  });

  it("refuses a file", async () => {
    const file = join(dir, "a-file");
    writeFileSync(file, "");
    const err = await expectVaultError(
      () => assertRuntimeDir({ path: file, source: "--runtime-dir" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(`--runtime-dir: not a directory: ${file}`);
  });

  // The owner and mode checks need a uid and honoured mode bits: win32 has
  // neither (no process.geteuid; stat reports uid 0 and a synthesized 0666).
  it.skipIf(process.platform === "win32")(
    "accepts mkdtemp's 0700 directory owned by this user",
    () => {
      expect(() => assertRuntimeDir({ path: dir, source: "--runtime-dir" })).not.toThrow();
    },
  );

  it.skipIf(process.platform === "win32")("accepts a 0750 directory (chmod; POSIX only)", () => {
    chmodSync(dir, 0o750);
    expect(() => assertRuntimeDir({ path: dir, source: "--runtime-dir" })).not.toThrow();
  });

  it.skipIf(process.platform === "win32").each([
    { mode: 0o770, octal: "0770" },
    { mode: 0o755, octal: "0755" },
    { mode: 0o751, octal: "0751" },
  ])("refuses a $octal directory (chmod; POSIX only)", async ({ mode, octal }) => {
    chmodSync(dir, mode);
    const err = await expectVaultError(
      () => assertRuntimeDir({ path: dir, source: "--runtime-dir" }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `--runtime-dir: mode ${octal} is not 0750 or stricter (group-writable or world-accessible): ${dir}`,
    );
  });

  // The filesystem root is root-owned on Linux and macOS: a directory another
  // user owns without a chown, which needs root. Skipped where the suite runs
  // as root, which owns it too.
  it.skipIf(process.platform === "win32" || process.geteuid?.() === 0)(
    "refuses a directory another user owns (the filesystem root; POSIX only)",
    async () => {
      const root = parse(dir).root;
      const err = await expectVaultError(
        () => assertRuntimeDir({ path: root, source: "--runtime-dir" }),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `--runtime-dir: owned by uid 0, not by this process's uid ${String(process.geteuid?.())}: ${root}`,
      );
    },
  );

  it.runIf(process.platform === "win32")(
    "refuses an existing directory on Windows: the owner and mode cannot be checked",
    async () => {
      const err = await expectVaultError(
        () => assertRuntimeDir({ path: dir, source: "--runtime-dir" }),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `--runtime-dir: not supported on this platform (the owner and mode cannot be checked): ${dir}`,
      );
    },
  );
});

describe("consumerDir", () => {
  it.each(["alice", "ci_bot-2"])("places consumer %j under the runtime directory", (name) => {
    expect(consumerDir("/run/harpoc", name)).toBe(join("/run/harpoc", name));
  });

  it.each([
    { name: "..", why: "a parent step" },
    { name: "a/b", why: "slash-bearing" },
    { name: "a\\b", why: "backslash-bearing" },
    { name: "-x", why: "dash-led" },
    { name: "", why: "empty" },
    { name: "Alice", why: "uppercase" },
    { name: "a".repeat(256), why: "256 characters long" },
  ])("refuses a consumer name that is $why", async ({ name }) => {
    const err = await expectVaultError(
      () => consumerDir("/run/harpoc", name),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `consumer ${JSON.stringify(name)}: not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)`,
    );
  });
});

describe("assertConsumerDir", () => {
  it("refuses a missing consumer directory", async () => {
    const missing = consumerDir(dir, "alice");
    const err = await expectVaultError(() => assertConsumerDir(missing), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(`consumer directory: no such directory: ${missing}`);
  });

  it.skipIf(process.platform === "win32")(
    "accepts a 0750 consumer directory (chmod; POSIX only)",
    () => {
      const alice = consumerDir(dir, "alice");
      mkdirSync(alice);
      chmodSync(alice, 0o750);
      expect(() => assertConsumerDir(alice)).not.toThrow();
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses a group-writable consumer directory (chmod 0770; POSIX only)",
    async () => {
      const alice = consumerDir(dir, "alice");
      mkdirSync(alice);
      chmodSync(alice, 0o770);
      const err = await expectVaultError(() => assertConsumerDir(alice), ErrorCode.INVALID_INPUT);
      expect(err.message).toBe(
        `consumer directory: mode 0770 is not 0750 or stricter (group-writable or world-accessible): ${alice}`,
      );
    },
  );
});
