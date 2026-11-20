import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InjectionPolicy, SmtpAction } from "@harpoc/shared";
import { ActionType, ErrorCode, injectionPolicyInputSchema } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { DaemonPaths } from "./local-path.js";
import { namesDevice, namesNetworkShare } from "./local-path.js";
import type { SmtpSendOptions } from "./mail/smtp-client.js";
import type { SmtpInjectorDeps } from "./smtp-injector.js";
import { SmtpInjector } from "./smtp-injector.js";

const SECRET = "smtpuser:S3CRET-TOKEN-xyz";
const B = "\\";
const WIN32 = process.platform === "win32";
const IN_VAULT = "Attachment rejected: an attachment path is inside the vault directory";
const DEVICE = "Attachment rejected: an attachment path names a device";
const SHARE = "Attachment rejected: an attachment path names a network share";
const NOT_FILE = "Attachment rejected: an attachment path is not a regular file";
const NOT_LISTED =
  "Attachment rejected: an attachment path is not inside a directory the secret's policy lists";

let root: string;
let vaultDir: string;
let sessionDir: string;
let outsideDir: string;
let listedDir: string;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-attach-")));
  vaultDir = join(root, "vault");
  sessionDir = join(root, "session");
  outsideDir = join(root, "outside");
  listedDir = join(root, "listed");
  for (const dir of [vaultDir, join(vaultDir, "sub"), sessionDir, outsideDir, listedDir]) {
    mkdirSync(dir);
  }
  writeFileSync(join(vaultDir, "default.vault.db"), "S3CRET-TOKEN-xyz-db");
  writeFileSync(join(vaultDir, "sub", "note.txt"), "inside");
  writeFileSync(join(sessionDir, "session.json"), "S3CRET-TOKEN-xyz-session");
  writeFileSync(join(outsideDir, "report.txt"), "quarterly report");
  writeFileSync(join(listedDir, "report.txt"), "listed report");
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function action(...paths: string[]): SmtpAction {
  return {
    type: ActionType.SMTP,
    host: "127.0.0.1",
    security: "tls",
    from: "sender@example.com",
    to: ["to@example.com"],
    subject: "hi",
    text: "body",
    attachments: paths.map((path) => ({ path })),
  };
}

function policy(...localDirs: string[]): InjectionPolicy {
  return injectionPolicyInputSchema.parse({
    host_allowlist: ["127.0.0.1"],
    smtp_recipient_allowlist: ["*@example.com"],
    local_dirs: localDirs,
  });
}

const POLICY: InjectionPolicy = policy();

interface Counted {
  deps: Required<Pick<SmtpInjectorDeps, "sendSmtp" | "realpath" | "stat" | "readFile">>;
  realpaths: string[];
  stats: string[];
  reads: string[];
  sends: SmtpSendOptions[];
}

function counted(): Counted {
  const c: Counted = {
    realpaths: [],
    stats: [],
    reads: [],
    sends: [],
    deps: {
      sendSmtp: (opts) => {
        c.sends.push(opts);
        return Promise.resolve({ accepted: opts.envelope.recipients.length, messageId: null });
      },
      realpath: (p) => {
        c.realpaths.push(p);
        return realpath(p);
      },
      stat: (p) => {
        c.stats.push(p);
        return stat(p);
      },
      readFile: (p) => {
        c.reads.push(p);
        return readFile(p);
      },
    },
  };
  return c;
}

function vaultInjector(c: Counted, daemon?: DaemonPaths): SmtpInjector {
  return new SmtpInjector({
    ...c.deps,
    vaultFiles: [join(vaultDir, "default.vault.db"), join(sessionDir, "session.json")],
    ...(daemon !== undefined ? { daemon: () => daemon } : {}),
  });
}

async function expectRejected(
  c: Counted,
  injector: SmtpInjector,
  path: string,
  message: string,
  judgedUnder: InjectionPolicy = POLICY,
) {
  const err = await expectVaultError(
    () => injector.run(action(path), SECRET, judgedUnder, undefined, undefined),
    ErrorCode.ATTACHMENT_REJECTED,
  );
  expect(err.message).toBe(message);
  expect(c.stats).toEqual([]);
  expect(c.reads).toEqual([]);
  expect(c.sends).toEqual([]);
}

describe("SmtpInjector — attachments never come from the vault directory (B1)", () => {
  it("refuses the vault database file before any stat or read", async () => {
    const c = counted();
    await expectRejected(c, vaultInjector(c), join(vaultDir, "default.vault.db"), IN_VAULT);
  });

  it("refuses the session file in its own directory before any stat or read", async () => {
    const c = counted();
    await expectRejected(c, vaultInjector(c), join(sessionDir, "session.json"), IN_VAULT);
  });

  it("refuses any file below the vault directory", async () => {
    const c = counted();
    await expectRejected(c, vaultInjector(c), join(vaultDir, "sub", "note.txt"), IN_VAULT);
  });

  it("refuses a vault file reached through a directory link outside the vault (realpath)", async () => {
    const link = join(outsideDir, "innocent");
    symlinkSync(vaultDir, link, "junction");
    const c = counted();
    await expectRejected(c, vaultInjector(c), join(link, "default.vault.db"), IN_VAULT);
  });

  it.skipIf(process.platform !== "win32")(
    "refuses a vault file spelled in another case (win32 paths are case-insensitive)",
    async () => {
      const c = counted();
      await expectRejected(
        c,
        vaultInjector(c),
        join(vaultDir, "default.vault.db").toUpperCase(),
        IN_VAULT,
      );
    },
  );

  it("refuses a file in a vault directory created after the injector was constructed", async () => {
    const late = join(root, "late-vault");
    const c = counted();
    const injector = new SmtpInjector({ ...c.deps, vaultFiles: [join(late, "default.vault.db")] });
    mkdirSync(late);
    writeFileSync(join(late, "default.vault.db"), "S3CRET-TOKEN-xyz-late");

    await expectRejected(c, injector, join(late, "default.vault.db"), IN_VAULT);
  });

  it("refuses as inside the vault directory when a vault directory cannot be resolved (EACCES), before any stat, read or send", async () => {
    const denied = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    const c = counted();
    const injector = new SmtpInjector({
      ...c.deps,
      realpath: (p) => (p === vaultDir ? Promise.reject(denied) : c.deps.realpath(p)),
      vaultFiles: [join(vaultDir, "default.vault.db"), join(sessionDir, "session.json")],
    });

    await expectRejected(c, injector, join(outsideDir, "report.txt"), IN_VAULT, policy(outsideDir));
  });

  it("sends a file outside a vault directory that does not exist yet (ENOENT falls back to the resolved string)", async () => {
    const missing = join(root, "missing-vault");
    const c = counted();
    const injector = new SmtpInjector({
      ...c.deps,
      vaultFiles: [join(missing, "default.vault.db")],
    });

    await injector.run(
      action(join(outsideDir, "report.txt")),
      SECRET,
      policy(outsideDir),
      undefined,
      undefined,
    );

    expect(c.realpaths).toContain(missing);
    expect(c.sends).toHaveLength(1);
    expect(c.reads).toEqual([realpathSync.native(join(outsideDir, "report.txt"))]);
  });

  it("sends a regular file outside the vault directory, read from its resolved path, audited as given", async () => {
    const link = join(root, "via-link");
    symlinkSync(outsideDir, link, "junction");
    const given = join(link, "report.txt");
    const c = counted();

    const { auditDetails } = await vaultInjector(c).run(
      action(given),
      SECRET,
      policy(outsideDir),
      undefined,
      undefined,
    );

    expect(c.sends).toHaveLength(1);
    expect(c.reads).toEqual([realpathSync.native(given)]);
    expect(c.reads[0]).not.toBe(given);
    expect(auditDetails.attachment_paths).toEqual([given]);
    expect(auditDetails.attachment_total_bytes).toBe("quarterly report".length);
  });

  it("refuses a directory as not a regular file, before any read", async () => {
    const c = counted();
    const err = await expectVaultError(
      () => vaultInjector(c).run(action(outsideDir), SECRET, policy(root), undefined, undefined),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(err.message).toBe(NOT_FILE);
    expect(c.reads).toEqual([]);
    expect(c.sends).toEqual([]);
  });

  it.skipIf(process.platform === "win32")(
    "refuses a FIFO as not a regular file without blocking on it (POSIX — win32 has no mkfifo)",
    { timeout: 5_000 },
    async () => {
      const fifo = join(outsideDir, "pipe");
      expect(spawnSync("mkfifo", [fifo]).status).toBe(0);
      const c = counted();
      const err = await expectVaultError(
        () => vaultInjector(c).run(action(fifo), SECRET, policy(outsideDir), undefined, undefined),
        ErrorCode.ATTACHMENT_REJECTED,
      );
      expect(err.message).toBe(NOT_FILE);
      expect(c.reads).toEqual([]);
    },
  );

  it("an injector built without vault files still refuses devices and non-regular files, and sends the rest", async () => {
    const c = counted();
    const bare = new SmtpInjector(c.deps);
    const listingRoot = policy(root);

    await bare.run(
      action(join(vaultDir, "default.vault.db")),
      SECRET,
      listingRoot,
      undefined,
      undefined,
    );
    expect(c.sends).toHaveLength(1);

    const notFile = await expectVaultError(
      () => bare.run(action(vaultDir), SECRET, listingRoot, undefined, undefined),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(notFile.message).toBe(NOT_FILE);
    const device = process.platform === "win32" ? `${B}${B}.${B}NUL` : "/dev/null";
    const refused = await expectVaultError(
      () => bare.run(action(device), SECRET, listingRoot, undefined, undefined),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(refused.message).toBe(DEVICE);
  });

  it("a missing file inside the vault's directory is refused with the in-vault message, as an existing one is", async () => {
    for (const name of ["missing.vault.db", "default.vault.db"]) {
      const c = counted();
      await expectRejected(c, vaultInjector(c), join(vaultDir, name), IN_VAULT, policy(vaultDir));
    }
  });

  // On win32 both spellings fail ENOENT; off win32 the path through the regular file fails ENOTDIR.
  it.skipIf(WIN32)(
    "a path through a regular file inside the vault's directory is refused with the in-vault message, as one through a missing name is",
    async () => {
      for (const path of [
        join(vaultDir, "default.vault.db", "x"),
        join(vaultDir, "missing", "x"),
      ]) {
        const c = counted();
        await expectRejected(c, vaultInjector(c), path, IN_VAULT, policy(vaultDir));
      }
    },
  );
});

describe("SmtpInjector — attachments come only from a directory the secret's policy lists", () => {
  it("a file in no listed directory is refused, whether or not it exists", async () => {
    const present = join(outsideDir, "report.txt");
    const c = counted();
    await expectRejected(c, vaultInjector(c), present, NOT_LISTED, policy(listedDir));
    expect(c.realpaths).toContain(present);
    const d = counted();
    await expectRejected(
      d,
      vaultInjector(d),
      join(outsideDir, "missing.txt"),
      NOT_LISTED,
      policy(listedDir),
    );
  });

  it("an empty list sends no attachment", async () => {
    const c = counted();
    await expectRejected(c, vaultInjector(c), join(listedDir, "report.txt"), NOT_LISTED, POLICY);
  });

  it("a file in no listed directory after one in a listed directory refuses the send, before any stat or read of either", async () => {
    const c = counted();
    const err = await expectVaultError(
      () =>
        vaultInjector(c).run(
          action(join(listedDir, "report.txt"), join(outsideDir, "report.txt")),
          SECRET,
          policy(listedDir),
          undefined,
          undefined,
        ),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(err.message).toBe(NOT_LISTED);
    expect(c.stats).toEqual([]);
    expect(c.reads).toEqual([]);
    expect(c.sends).toEqual([]);
  });

  it("a missing file inside a listed directory is that refusal, not FILE_IO_ERROR", async () => {
    const c = counted();
    await expectRejected(
      c,
      vaultInjector(c),
      join(listedDir, "missing.txt"),
      NOT_LISTED,
      policy(listedDir),
    );
  });

  it("an attachment whose name holds a glob character is sent as named", async () => {
    // `*` and `?` are no file-name characters on win32.
    const names = WIN32 ? ["report[1].txt"] : ["report[1].txt", "a*.txt", "q?.txt"];
    for (const name of names) writeFileSync(join(listedDir, name), name);
    const c = counted();
    const given = names.map((name) => join(listedDir, name));
    await vaultInjector(c).run(action(...given), SECRET, policy(listedDir), undefined, undefined);
    expect(c.sends).toHaveLength(1);
    expect(c.reads).toEqual(given);
  });

  it.runIf(WIN32)("a reserved Windows name is a device (win32)", async () => {
    const c = counted();
    await expectRejected(
      c,
      vaultInjector(c),
      `C:${B}Users${B}a${B}NUL`,
      DEVICE,
      policy(`C:${B}Users${B}a`),
    );
    expect(c.realpaths).toEqual([]);
  });

  it("a relative path and //server/share/f are refused before any file-system call", async () => {
    // Off win32 `//server/share/f` is an absolute path of its own; there it is judged as any other.
    const cases: ReadonlyArray<readonly [string, string]> = [
      ["report.txt", NOT_LISTED],
      ...(WIN32
        ? ([
            ["//server/share/f", SHARE],
            ["//server", NOT_LISTED],
          ] as const)
        : []),
    ];
    for (const [path, message] of cases) {
      const c = counted();
      await expectRejected(c, vaultInjector(c), path, message, policy(listedDir));
      expect(c.realpaths).toEqual([]);
    }
  });

  it("with a daemon an attachment in a declared directory refuses with the in-vault message", async () => {
    const given = join(listedDir, "report.txt");
    const sent = counted();
    await vaultInjector(sent).run(action(given), SECRET, policy(listedDir), undefined, undefined);
    expect(sent.sends).toHaveLength(1);
    const c = counted();
    await expectRejected(
      c,
      vaultInjector(c, { protectedDirs: [listedDir], protectedFiles: [] }),
      given,
      IN_VAULT,
      policy(listedDir),
    );
  });

  it.skipIf(WIN32)(
    "with a daemon an attachment in a 0775 listed directory refuses with the list message, without one it sends (POSIX modes)",
    async () => {
      const given = join(listedDir, "report.txt");
      const noPaths: DaemonPaths = { protectedDirs: [], protectedFiles: [] };
      chmodSync(listedDir, 0o775);
      const sent = counted();
      await vaultInjector(sent).run(action(given), SECRET, policy(listedDir), undefined, undefined);
      expect(sent.sends).toHaveLength(1);
      const c = counted();
      await expectRejected(c, vaultInjector(c, noPaths), given, NOT_LISTED, policy(listedDir));
      chmodSync(listedDir, 0o755);
      const held = counted();
      await vaultInjector(held, noPaths).run(
        action(given),
        SECRET,
        policy(listedDir),
        undefined,
        undefined,
      );
      expect(held.sends).toHaveLength(1);
    },
  );
});

describe("SmtpInjector — attachments never come from a device or a network share (B1)", () => {
  const win32Devices = [
    `${B}${B}.${B}NUL`,
    "//./NUL",
    `/${B}./NUL`,
    `${B}${B}?${B}GLOBALROOT${B}Device${B}Null`,
    "//?/GLOBALROOT/Device/Null",
    `${B}${B}.${B}CONIN$`,
    `${B}${B}.${B}pipe${B}harpoc-probe`,
  ];
  for (const path of win32Devices) {
    it.skipIf(process.platform !== "win32")(
      `refuses ${JSON.stringify(path)} as a device before any filesystem call (win32)`,
      async () => {
        const c = counted();
        await expectRejected(c, vaultInjector(c), path, DEVICE);
        expect(c.realpaths).toEqual([]);
      },
    );
  }

  const win32Shares = [
    `${B}${B}harpoc-unreachable.invalid${B}share${B}f.txt`,
    "//harpoc-unreachable.invalid/share/f.txt",
  ];
  for (const path of win32Shares) {
    it.skipIf(process.platform !== "win32")(
      `refuses ${JSON.stringify(path)} as a network share before any filesystem call (win32)`,
      async () => {
        const c = counted();
        await expectRejected(c, vaultInjector(c), path, SHARE);
        expect(c.realpaths).toEqual([]);
      },
    );
  }

  const posixDevices = [
    "/dev/zero",
    "/dev/stdin",
    "//dev/zero",
    "/tmp/../dev/zero",
    "/proc/self/environ",
    "/sys/kernel/notes",
  ];
  for (const path of posixDevices) {
    it.skipIf(process.platform === "win32")(
      `refuses ${JSON.stringify(path)} as a device before any filesystem call (POSIX)`,
      async () => {
        const c = counted();
        await expectRejected(c, vaultInjector(c), path, DEVICE);
        expect(c.realpaths).toEqual([]);
      },
    );
  }

  it.skipIf(process.platform === "win32")(
    "refuses a link in a listed directory to /dev/zero, a target no listed directory holds, with the list message (POSIX — win32 has no /dev)",
    async () => {
      const link = join(outsideDir, "zero");
      symlinkSync("/dev/zero", link);
      const c = counted();
      await expectRejected(c, vaultInjector(c), link, NOT_LISTED, policy(outsideDir));
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses a device below a listed directory that is itself a link to /dev, with the list message (POSIX — win32 has no /dev)",
    async () => {
      const link = join(outsideDir, "to-dev");
      symlinkSync("/dev", link);
      const c = counted();
      await expectRejected(c, vaultInjector(c), join(link, "zero"), NOT_LISTED, policy(link));
    },
  );

  it("names the win32 device namespaces and shares, on any host", () => {
    for (const path of win32Devices) expect(namesDevice(path, "win32"), path).toBe(true);
    for (const path of win32Shares) {
      expect(namesDevice(path, "win32"), path).toBe(false);
      expect(namesNetworkShare(path, "win32"), path).toBe(true);
    }
    const unc = `${B}${B}?${B}UNC${B}server${B}share${B}f.txt`;
    expect(namesDevice(unc, "win32")).toBe(false);
    expect(namesNetworkShare(unc, "win32")).toBe(true);
    for (const path of [`C:${B}Users${B}a${B}NUL`, "C:/reports/q3.pdf", "/dev/zero"]) {
      expect(namesDevice(path, "win32"), path).toBe(false);
      expect(namesNetworkShare(path, "win32"), path).toBe(false);
    }
  });

  it("names the POSIX device trees and nothing else, on any host", () => {
    for (const path of [...posixDevices, "/dev", "/proc", "/sys"]) {
      expect(namesDevice(path, "linux"), path).toBe(true);
    }
    for (const path of [
      "/devices/x",
      "/home/u/dev/x",
      "/srv/proc",
      "//server/share/f",
      `${B}${B}.${B}NUL`,
    ]) {
      expect(namesDevice(path, "linux"), path).toBe(false);
      expect(namesNetworkShare(path, "linux"), path).toBe(false);
    }
  });
});
