import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InjectionPolicy, SmtpAction } from "@harpoc/shared";
import { ActionType, ErrorCode, injectionPolicyInputSchema } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { SmtpSendOptions } from "./mail/smtp-client.js";
import type { SmtpInjectorDeps } from "./smtp-injector.js";
import { SmtpInjector, namesDevice, namesNetworkShare } from "./smtp-injector.js";

const SECRET = "smtpuser:S3CRET-TOKEN-xyz";
const B = "\\";
const IN_VAULT = "Attachment rejected: an attachment path is inside the vault directory";
const DEVICE = "Attachment rejected: an attachment path names a device";
const SHARE = "Attachment rejected: an attachment path names a network share";
const NOT_FILE = "Attachment rejected: an attachment path is not a regular file";

let root: string;
let vaultDir: string;
let sessionDir: string;
let outsideDir: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "harpoc-attach-"));
  vaultDir = join(root, "vault");
  sessionDir = join(root, "session");
  outsideDir = join(root, "outside");
  for (const dir of [vaultDir, join(vaultDir, "sub"), sessionDir, outsideDir]) mkdirSync(dir);
  writeFileSync(join(vaultDir, "default.vault.db"), "S3CRET-TOKEN-xyz-db");
  writeFileSync(join(vaultDir, "sub", "note.txt"), "inside");
  writeFileSync(join(sessionDir, "session.json"), "S3CRET-TOKEN-xyz-session");
  writeFileSync(join(outsideDir, "report.txt"), "quarterly report");
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

const POLICY: InjectionPolicy = injectionPolicyInputSchema.parse({
  host_allowlist: ["127.0.0.1"],
  smtp_recipient_allowlist: ["*@example.com"],
});

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

function vaultInjector(c: Counted): SmtpInjector {
  return new SmtpInjector({
    ...c.deps,
    vaultFiles: [join(vaultDir, "default.vault.db"), join(sessionDir, "session.json")],
  });
}

async function expectRejected(c: Counted, injector: SmtpInjector, path: string, message: string) {
  const err = await expectVaultError(
    () => injector.run(action(path), SECRET, POLICY, undefined, undefined),
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

  it("rejects with the realpath error of a vault directory it cannot resolve (EACCES), before any stat, read or send", async () => {
    const denied = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    const c = counted();
    const injector = new SmtpInjector({
      ...c.deps,
      realpath: (p) => (p === vaultDir ? Promise.reject(denied) : c.deps.realpath(p)),
      vaultFiles: [join(vaultDir, "default.vault.db"), join(sessionDir, "session.json")],
    });

    await expect(
      injector.run(action(join(outsideDir, "report.txt")), SECRET, POLICY, undefined, undefined),
    ).rejects.toBe(denied);
    expect(c.stats).toEqual([]);
    expect(c.reads).toEqual([]);
    expect(c.sends).toEqual([]);
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
      POLICY,
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
      POLICY,
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
      () => vaultInjector(c).run(action(outsideDir), SECRET, POLICY, undefined, undefined),
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
        () => vaultInjector(c).run(action(fifo), SECRET, POLICY, undefined, undefined),
        ErrorCode.ATTACHMENT_REJECTED,
      );
      expect(err.message).toBe(NOT_FILE);
      expect(c.reads).toEqual([]);
    },
  );

  it("an injector built without vault files still refuses devices and non-regular files, and sends the rest", async () => {
    const c = counted();
    const bare = new SmtpInjector(c.deps);

    await bare.run(
      action(join(vaultDir, "default.vault.db")),
      SECRET,
      POLICY,
      undefined,
      undefined,
    );
    expect(c.sends).toHaveLength(1);

    const notFile = await expectVaultError(
      () => bare.run(action(vaultDir), SECRET, POLICY, undefined, undefined),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(notFile.message).toBe(NOT_FILE);
    const device = process.platform === "win32" ? `${B}${B}.${B}NUL` : "/dev/null";
    const refused = await expectVaultError(
      () => bare.run(action(device), SECRET, POLICY, undefined, undefined),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(refused.message).toBe(DEVICE);
  });
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
    "refuses a link outside the vault that resolves into /dev (POSIX)",
    async () => {
      const link = join(outsideDir, "zero");
      symlinkSync("/dev/zero", link);
      const c = counted();
      await expectRejected(c, vaultInjector(c), link, DEVICE);
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
