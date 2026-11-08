import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, parse } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import {
  agentSocketPipeName,
  assertConsumerDir,
  assertConsumerName,
  assertRuntimeDir,
  consumerDir,
  consumerDirs,
  consumerSocketPaths,
  isPrivateDirMode,
  resolveRuntimeDir,
  WINDOWS_CONSUMER_DIR_RIGHTS,
  windowsDirAclRefusal,
} from "./runtime-dir.js";
import { expectVaultError } from "@harpoc/test-utils";

/** `icacls /inheritance:r` with this account, SYSTEM and Administrators full — the recipe's base. */
const TRUSTED_GRANTS = [
  "/inheritance:r",
  "/grant:r",
  `${userInfo().username}:(OI)(CI)F`,
  "/grant:r",
  "*S-1-5-18:(OI)(CI)F",
  "/grant:r",
  "*S-1-5-32-544:(OI)(CI)F",
];

function icacls(path: string, ...args: string[]): void {
  const res = spawnSync(
    `${process.env.SystemRoot as string}\\System32\\icacls.exe`,
    [path, ...args],
    {
      shell: false,
      windowsHide: true,
      timeout: 15_000,
      encoding: "utf8",
    },
  );
  if (res.status !== 0) {
    expect.fail(
      `icacls ${[path, ...args].join(" ")} exited ${String(res.status)}${res.error === undefined ? "" : ` (${res.error.message})`}: ${res.stderr}`,
    );
  }
}

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
      expect(resolveRuntimeDir(undefined, env, "linux")).toBeUndefined();
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

  // B7: the win32 check reads the access list by SID (flipped from B1's refusal, RD-3). A
  // directory under this user's temporary directory inherits this account, SYSTEM and
  // Administrators only.
  it.runIf(process.platform === "win32")(
    "accepts this user's own temporary directory on Windows: owner and every grant this account, SYSTEM or Administrators",
    () => {
      expect(() => assertRuntimeDir({ path: dir, source: "--runtime-dir" })).not.toThrow();
    },
  );

  it.runIf(process.platform === "win32")(
    "refuses a directory granting another SID on Windows, naming the SID and its mask",
    async () => {
      icacls(dir, ...TRUSTED_GRANTS, "/grant:r", "*S-1-5-11:(RX)");
      const err = await expectVaultError(
        () => assertRuntimeDir({ path: dir, source: "--runtime-dir" }),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `--runtime-dir: the access list grants S-1-5-11 0x001200A9; only this process's account, SYSTEM, Administrators may hold a grant: ${dir}`,
      );
    },
  );

  it.runIf(process.platform === "win32")(
    "refuses a directory under %ProgramData% that keeps its inherited grants (no /inheritance:r)",
    async () => {
      const root = mkdtempSync(join(process.env.ProgramData as string, "harpoc-runtime-dir-"));
      try {
        const err = await expectVaultError(
          () => assertRuntimeDir({ path: root, source: "%ProgramData%" }),
          ErrorCode.INVALID_INPUT,
        );
        expect(err.message).toMatch(
          /^%ProgramData%: the access list grants S-1-[0-9-]+ 0x[0-9A-F]{8} \(inherited\); only this process's account, SYSTEM, Administrators may hold a grant: /,
        );
      } finally {
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    },
  );
});

describe("resolveRuntimeDir on win32 (the platform passed)", () => {
  it("defaults to %ProgramData%\\harpoc\\run when the caller hands an environment holding ProgramData", () => {
    expect(resolveRuntimeDir(undefined, { ProgramData: "C:\\ProgramData" }, "win32")).toEqual({
      path: "C:\\ProgramData\\harpoc\\run",
      source: "%ProgramData%",
    });
  });

  it("the option still wins, and a caller that asks for no ambient read (undefined) resolves nothing", () => {
    expect(resolveRuntimeDir("D:\\run", { ProgramData: "C:\\ProgramData" }, "win32")).toEqual({
      path: "D:\\run",
      source: "--runtime-dir",
    });
    expect(resolveRuntimeDir(undefined, undefined, "win32")).toBeUndefined();
  });

  it("systemd's $RUNTIME_DIRECTORY, when set, still wins on win32; ProgramData is read on win32 only", () => {
    expect(
      resolveRuntimeDir(
        undefined,
        { RUNTIME_DIRECTORY: "\\srv\\run", ProgramData: "C:\\ProgramData" },
        "win32",
      ),
    ).toEqual({ path: "\\srv\\run", source: "$RUNTIME_DIRECTORY" });
    expect(
      resolveRuntimeDir(undefined, { ProgramData: "C:\\ProgramData" }, "linux"),
    ).toBeUndefined();
  });

  it.each([{ ProgramData: "" }, { ProgramData: "ProgramData" }, {}])(
    "refuses an ambient environment whose ProgramData is unset, empty or not an absolute path (%j)",
    async (env) => {
      const err = await expectVaultError(
        () => resolveRuntimeDir(undefined, env, "win32"),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        "%ProgramData% is not set to an absolute path; name the runtime directory with --runtime-dir",
      );
    },
  );
});

describe("agentSocketPipeName", () => {
  it.each(["alice", "ci_bot-2"])(
    "names consumer %j's pipe \\\\.\\pipe\\harpoc-<consumer>-ssh-agent",
    (name) => {
      expect(agentSocketPipeName(name)).toBe(`\\\\.\\pipe\\harpoc-${name}-ssh-agent`);
    },
  );

  it("refuses a name that is not a consumer name with consumerDir's message", async () => {
    const err = await expectVaultError(() => agentSocketPipeName("a\\b"), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(
      'consumer "a\\\\b": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    );
  });

  it("refuses a consumer whose pipe name would pass 256 characters", async () => {
    const name = "a".repeat(231);
    const err = await expectVaultError(() => agentSocketPipeName(name), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(
      `consumer "${name}": the pipe name is 257 characters, over the 256 a pipe name holds: \\\\.\\pipe\\harpoc-${name}-ssh-agent`,
    );
    expect(agentSocketPipeName("a".repeat(230))).toHaveLength(256);
  });
});

describe("windowsDirAclRefusal (a listing by SID, every platform)", () => {
  const ME = "S-1-5-21-2619733007-1928661584-3550714090-1001";
  const AGENT = "S-1-5-21-2619733007-1928661584-3550714090-1002";
  const full = (sid: string, inherited = false) => ({
    allow: true,
    sid,
    rights: 0x1f01ff,
    inherited,
    inheritance: 3,
    propagation: 0,
  });
  /** The consumer directory install-two-identity.ps1 leaves (measured, icacls /inheritance:r). */
  const layout = (rules = [full("S-1-5-18"), full("S-1-5-32-544"), full(ME)]) => ({
    user: ME,
    owner: ME,
    account: AGENT,
    rules,
  });
  const consumerRx = {
    allow: true,
    sid: AGENT,
    rights: 0x1200a9,
    inherited: false,
    inheritance: 3,
    propagation: 0,
  };

  it("exports the consumer's cap as the unsigned mask 0xA01200A9: (RX), GENERIC_READ and GENERIC_EXECUTE", () => {
    expect(WINDOWS_CONSUMER_DIR_RIGHTS).toBe(0xa01200a9);
  });

  it("accepts the recipe's consumer directory: three trusted SIDs full, the consumer read and execute", () => {
    expect(windowsDirAclRefusal(layout([...layout().rules, consumerRx]), "agent1")).toBeUndefined();
  });

  it("accepts an owner of SYSTEM or Administrators — an elevated administrator's directory", () => {
    expect(windowsDirAclRefusal({ ...layout(), owner: "S-1-5-32-544" }, "agent1")).toBeUndefined();
    expect(windowsDirAclRefusal({ ...layout(), owner: "S-1-5-18" }, "agent1")).toBeUndefined();
  });

  it("refuses another owner, naming it", () => {
    expect(windowsDirAclRefusal({ ...layout(), owner: AGENT }, "agent1")).toBe(
      `owned by ${AGENT}, not by this process's account ${ME}, SYSTEM or Administrators`,
    );
  });

  it("refuses a consumer granted write, naming the mask (icacls (RX,W) is 0x001201BF)", () => {
    expect(
      windowsDirAclRefusal(
        layout([...layout().rules, { ...consumerRx, rights: 0x1201bf }]),
        "agent1",
      ),
    ).toBe(
      `the access list grants the consumer agent1 (${AGENT}) 0x001201BF; read and execute (0x001200A9) at most`,
    );
  });

  it("accepts a consumer's inherit-only generic read and execute, refuses its generic write", () => {
    const io = { ...consumerRx, rights: 0xa0000000, inheritance: 3, propagation: 2 };
    expect(windowsDirAclRefusal(layout([...layout().rules, io]), "agent1")).toBeUndefined();
    expect(
      windowsDirAclRefusal(layout([...layout().rules, { ...io, rights: 0x40000000 }]), "agent1"),
    ).toBe(
      `the access list grants the consumer agent1 (${AGENT}) 0x40000000; read and execute (0x001200A9) at most`,
    );
  });

  it("refuses a stray grant — the consumer's SID on the runtime directory included", () => {
    expect(windowsDirAclRefusal(layout([...layout().rules, consumerRx]), undefined)).toBe(
      `the access list grants ${AGENT} 0x001200A9; only this process's account, SYSTEM, Administrators may hold a grant`,
    );
  });

  it("refuses %ProgramData%'s inherited grants (CREATOR OWNER, BUILTIN\\Users), marked inherited", () => {
    const inheritedFromProgramData = [
      full("S-1-5-18", true),
      full("S-1-5-32-544", true),
      {
        allow: true,
        sid: "S-1-3-0",
        rights: 0x10000000,
        inherited: true,
        inheritance: 3,
        propagation: 2,
      },
      {
        allow: true,
        sid: "S-1-5-32-545",
        rights: 0x1200a9,
        inherited: true,
        inheritance: 3,
        propagation: 0,
      },
    ];
    expect(windowsDirAclRefusal(layout(inheritedFromProgramData), "agent1")).toBe(
      "the access list grants S-1-3-0 0x10000000 (inherited); only this process's account, SYSTEM, Administrators and the consumer may hold a grant",
    );
  });

  it("ignores a deny rule", () => {
    const deny = { ...consumerRx, allow: false, sid: "S-1-1-0", rights: 0x1f01ff };
    expect(windowsDirAclRefusal(layout([...layout().rules, deny]), "agent1")).toBeUndefined();
  });

  it("refuses a consumer directory whose name names no local account, or a well-known group", () => {
    expect(windowsDirAclRefusal({ ...layout(), account: null }, "agent1")).toBe(
      'no local account is named "agent1" (a consumer directory is named for its agent user)',
    );
    expect(windowsDirAclRefusal({ ...layout(), account: "S-1-1-0" }, "everyone")).toBe(
      '"everyone" names S-1-1-0, not a user account',
    );
  });
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

describe("assertConsumerName", () => {
  // RD-B7-5: on win32 a directory named nul is created, but the access-list read of it lists the
  // NUL device's rules — the directory check would judge the wrong object.
  it
    .runIf(process.platform === "win32")
    .each(["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"])(
    "refuses the reserved device name %j on Windows",
    async (name) => {
      const err = await expectVaultError(() => assertConsumerName(name), ErrorCode.INVALID_INPUT);
      expect(err.message).toBe(
        `consumer ${JSON.stringify(name)}: not a directory name on Windows (a reserved device name: con, prn, aux, nul, com1-com9, lpt1-lpt9)`,
      );
    },
  );

  it.runIf(process.platform === "win32")(
    "on Windows a device name's neighbours stay consumer names (com0, com10, nul1, console)",
    () => {
      for (const name of ["com0", "com10", "nul1", "console"]) {
        expect(() => assertConsumerName(name)).not.toThrow();
      }
    },
  );

  // POSIX: nul is an ordinary directory name there; the path stays unchanged.
  it.skipIf(process.platform === "win32")("accepts nul and com1 off Windows", () => {
    expect(() => assertConsumerName("nul")).not.toThrow();
    expect(() => assertConsumerName("com1")).not.toThrow();
  });

  it("accepts a consumer name and refuses any other with consumerDir's message", async () => {
    expect(() => assertConsumerName("ci_bot-2")).not.toThrow();
    const err = await expectVaultError(() => assertConsumerName("Alice"), ErrorCode.INVALID_INPUT);
    expect(err.message).toBe(
      'consumer "Alice": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    );
  });
});

describe("consumerSocketPaths", () => {
  const source = "--runtime-dir" as const;

  /** A consumer directory as the recipe leaves it: this user's own, 0750 whatever the umask. */
  function consumer(name: string): string {
    const path = join(dir, name);
    mkdirSync(path);
    chmodSync(path, 0o750);
    return path;
  }

  it("lists nothing under a runtime directory without consumer directories", () => {
    writeFileSync(join(dir, "a-file"), "");
    expect(consumerSocketPaths({ path: dir, source }, "proxy.sock")).toEqual([]);
  });

  // The name and length checks come before the filesystem assertion: they run on win32 too.
  it("refuses a directory whose name is not a consumer name, before any directory is asserted", async () => {
    mkdirSync(join(dir, "Alice"));
    const err = await expectVaultError(
      () => consumerSocketPaths({ path: dir, source }, "proxy.sock"),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      'consumer "Alice": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    );
  });

  // unix(7): Linux's sun_path is 108 bytes, the terminating NUL included (X-3).
  it("refuses a consumer whose socket path would not fit a Unix socket address", async () => {
    const name = "a".repeat(100);
    mkdirSync(join(dir, name));
    const path = join(dir, name, "proxy.sock");
    const err = await expectVaultError(
      () => consumerSocketPaths({ path: dir, source }, "proxy.sock"),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `consumer "${name}": the socket path is ${String(Buffer.byteLength(path))} bytes, over the 107 a Unix socket path holds: ${path}`,
    );
  });

  it("names the runtime directory's source when it cannot be listed", async () => {
    const missing = join(dir, "missing");
    const err = await expectVaultError(
      () => consumerSocketPaths({ path: missing, source: "$RUNTIME_DIRECTORY" }, "proxy.sock"),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      `$RUNTIME_DIRECTORY: the consumer directories cannot be listed: ${missing}`,
    );
  });

  it.skipIf(process.platform === "win32")(
    "composes <consumer>/<socket> for every consumer directory, by name, other entries ignored (POSIX)",
    () => {
      consumer("bob");
      consumer("alice");
      writeFileSync(join(dir, "a-file"), "");
      expect(consumerSocketPaths({ path: dir, source }, "proxy.sock")).toEqual([
        join(dir, "alice", "proxy.sock"),
        join(dir, "bob", "proxy.sock"),
      ]);
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses a consumer directory assertConsumerDir refuses — never skipped (POSIX)",
    async () => {
      consumer("alice");
      chmodSync(consumer("bob"), 0o755);
      const err = await expectVaultError(
        () => consumerSocketPaths({ path: dir, source }, "proxy.sock"),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `consumer directory: mode 0755 is not 0750 or stricter (group-writable or world-accessible): ${join(dir, "bob")}`,
      );
    },
  );
});

describe("consumerDirs", () => {
  const source = "--runtime-dir" as const;

  it("lists nothing under a runtime directory without consumer directories, other entries ignored", () => {
    writeFileSync(join(dir, "a-file"), "");
    expect(consumerDirs({ path: dir, source })).toEqual([]);
  });

  it("refuses a directory whose name is not a consumer name", async () => {
    mkdirSync(join(dir, "Alice"));
    const err = await expectVaultError(
      () => consumerDirs({ path: dir, source }),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      'consumer "Alice": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    );
  });

  it.skipIf(process.platform === "win32")(
    "lists every checked consumer directory by name, no SID (POSIX)",
    () => {
      for (const name of ["bob", "alice"]) {
        mkdirSync(join(dir, name));
        chmodSync(join(dir, name), 0o750);
      }
      expect(consumerDirs({ path: dir, source })).toEqual([
        { consumer: "alice", dir: join(dir, "alice") },
        { consumer: "bob", dir: join(dir, "bob") },
      ]);
    },
  );

  // The stand-in consumer is this account (a local account the runner and the desktop both have);
  // the consumer-rights rule is pinned on fixtures above (windowsDirAclRefusal).
  it.runIf(process.platform === "win32")(
    "on Windows each entry carries the account SID its directory's name names",
    (ctx) => {
      const name = userInfo().username.toLowerCase();
      let standsIn = true;
      try {
        assertConsumerName(name);
      } catch {
        standsIn = false;
      }
      ctx.skip(
        !standsIn,
        `this account's name ${JSON.stringify(name)} is not a consumer name (lowercase letters, digits, _ and -), so it cannot stand in for a consumer`,
      );
      mkdirSync(join(dir, name));
      icacls(join(dir, name), ...TRUSTED_GRANTS);
      const [entry, ...rest] = consumerDirs({ path: dir, source });
      expect(rest).toEqual([]);
      expect(entry?.consumer).toBe(name);
      expect(entry?.dir).toBe(join(dir, name));
      expect(entry?.sid).toMatch(/^S-1-5-21-\d+-\d+-\d+-\d+$/);
    },
  );

  it.runIf(process.platform === "win32")(
    "on Windows refuses a consumer directory whose name names no local account",
    async () => {
      mkdirSync(join(dir, "nosuchuser-b7"));
      const err = await expectVaultError(
        () => consumerDirs({ path: dir, source }),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        `consumer directory: no local account is named "nosuchuser-b7" (a consumer directory is named for its agent user): ${join(dir, "nosuchuser-b7")}`,
      );
    },
  );
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
