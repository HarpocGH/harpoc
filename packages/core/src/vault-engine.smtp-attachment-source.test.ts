import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SmtpAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const B = "\\";
const WIN32 = process.platform === "win32";
const DEVICE = "Attachment rejected: an attachment path names a device";
const SHARE = "Attachment rejected: an attachment path names a network share";
const NOT_LISTED =
  "Attachment rejected: an attachment path is not inside a directory the secret's policy lists";

let tempDir: string;
let engine: VaultEngine | undefined;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  tempDir = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-smtpsrc-")));
});

afterEach(async () => {
  await engine?.destroy();
  engine = undefined;
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function mailVault(
  dbPath: string,
  sessionPath: string,
  localDirs: string[] = [],
): Promise<VaultEngine> {
  engine = new VaultEngine({ dbPath, sessionPath });
  await engine.initVault("password");
  await engine.createSecret({
    name: "mail",
    type: "api_key",
    value: new Uint8Array(Buffer.from("ops@example.com:S3CRET-TOKEN-xyz")),
  });
  await engine.setInjectionPolicy("secret://mail", {
    host_allowlist: ["10.0.0.1"],
    smtp_recipient_allowlist: ["*@example.com"],
    local_dirs: localDirs,
  });
  return engine;
}

function send(path: string): SmtpAction {
  return {
    type: "smtp",
    host: "10.0.0.1",
    security: "tls",
    from: "ops@example.com",
    to: ["dev@example.com"],
    subject: "files",
    text: "attached",
    attachments: [{ path }],
  };
}

function gitDirectory(dir: string): void {
  mkdirSync(join(dir, "objects"), { recursive: true });
  mkdirSync(join(dir, "refs"));
  writeFileSync(join(dir, "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, "config"), "[core]\n");
}

function failedUseRows(vault: VaultEngine): (Record<string, unknown> | null)[] {
  return vault
    .queryAudit({ eventType: AuditEventType.SECRET_USE, success: false })
    .map((row) => row.detail);
}

describe("useSecret (smtp) — the engine's injector refuses the vault's own files (B1)", () => {
  for (const file of ["test.vault.db", "session.json"]) {
    it(`refuses ${file} as an attachment with a failed secret.use row`, async () => {
      const dir = join(tempDir, "vault");
      mkdirSync(dir);
      const vault = await mailVault(join(dir, "test.vault.db"), join(dir, "session.json"), [dir]);
      const path = join(dir, file);

      const err = await expectVaultError(
        () => vault.useSecret("secret://mail", send(path)),
        ErrorCode.ATTACHMENT_REJECTED,
      );

      expect(err.message).toBe(NOT_LISTED);
      expect(failedUseRows(vault)).toEqual([
        {
          context: "smtp",
          host: "10.0.0.1",
          from: "ops@example.com",
          recipients: ["dev@example.com"],
          attachment_paths: [path],
          attachment_total_bytes: 0,
          error: ErrorCode.ATTACHMENT_REJECTED,
        },
      ]);
    });
  }

  it("refuses the session file when it lives in a directory of its own", async () => {
    const dbDir = join(tempDir, "db");
    const sessionDir = join(tempDir, "session");
    mkdirSync(dbDir);
    mkdirSync(sessionDir);
    const vault = await mailVault(join(dbDir, "test.vault.db"), join(sessionDir, "session.json"), [
      sessionDir,
    ]);

    const err = await expectVaultError(
      () => vault.useSecret("secret://mail", send(join(sessionDir, "session.json"))),
      ErrorCode.ATTACHMENT_REJECTED,
    );

    expect(err.message).toBe(NOT_LISTED);
  });

  it("lets a file outside the vault directory past the source checks (refused later by the SSRF floor)", async () => {
    const dir = join(tempDir, "vault");
    const outside = join(tempDir, "outside");
    mkdirSync(dir);
    mkdirSync(outside);
    writeFileSync(join(outside, "report.txt"), "quarterly report");
    const vault = await mailVault(join(dir, "test.vault.db"), join(dir, "session.json"), [outside]);

    await expectVaultError(
      () => vault.useSecret("secret://mail", send(join(outside, "report.txt"))),
      ErrorCode.SSRF_BLOCKED,
    );
  });

  it("lets a work tree's file beside its `.git` past the source checks (refused later by the SSRF floor)", async () => {
    const dir = join(tempDir, "vault");
    const tree = join(tempDir, "tree");
    mkdirSync(dir);
    gitDirectory(join(tree, ".git"));
    writeFileSync(join(tree, "report.txt"), "work tree report");
    const vault = await mailVault(join(dir, "test.vault.db"), join(dir, "session.json"), [tree]);

    await expectVaultError(
      () => vault.useSecret("secret://mail", send(join(tree, "report.txt"))),
      ErrorCode.SSRF_BLOCKED,
    );
  });
});

describe("useSecret (smtp) — an attachment comes only from a directory the secret's policy lists", () => {
  let listed: string;
  let outside: string;

  beforeEach(() => {
    listed = join(tempDir, "listed");
    outside = join(tempDir, "outside");
    for (const dir of [join(tempDir, "vault"), listed, outside]) mkdirSync(dir);
    writeFileSync(join(listed, "report.txt"), "listed report");
    writeFileSync(join(outside, "report.txt"), "quarterly report");
    gitDirectory(join(listed, "bare.git"));
    gitDirectory(join(listed, "wt", ".git"));
    symlinkSync(join(listed, "wt", ".git"), join(listed, "to-dotgit"), "junction");
  });

  function vaultListing(...localDirs: string[]): Promise<VaultEngine> {
    const dir = join(tempDir, "vault");
    return mailVault(join(dir, "test.vault.db"), join(dir, "session.json"), localDirs);
  }

  async function expectOneRefusal(vault: VaultEngine, path: string, message: string) {
    const err = await expectVaultError(
      () => vault.useSecret("secret://mail", send(path)),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(err.message).toBe(message);
    expect(vault.queryAudit({ eventType: AuditEventType.SECRET_USE })).toHaveLength(1);
    expect(failedUseRows(vault)).toEqual([
      {
        context: "smtp",
        host: "10.0.0.1",
        from: "ops@example.com",
        recipients: ["dev@example.com"],
        attachment_paths: [path],
        attachment_total_bytes: 0,
        error: ErrorCode.ATTACHMENT_REJECTED,
      },
    ]);
  }

  type Refusal = readonly [string, () => { listedDirs: string[]; path: string; message: string }];

  async function refusesWithOneRow(_label: string, refusal: Refusal[1]) {
    const { listedDirs, path, message } = refusal();
    await expectOneRefusal(await vaultListing(...listedDirs), path, message);
  }

  const REFUSALS: readonly Refusal[] = [
    [
      "a file in no listed directory",
      () => ({ listedDirs: [listed], path: join(outside, "report.txt"), message: NOT_LISTED }),
    ],
    [
      "a missing file inside a listed directory",
      () => ({ listedDirs: [listed], path: join(listed, "missing.txt"), message: NOT_LISTED }),
    ],
    [
      "a file under an empty list",
      () => ({ listedDirs: [], path: join(listed, "report.txt"), message: NOT_LISTED }),
    ],
    ["a relative path", () => ({ listedDirs: [listed], path: "report.txt", message: NOT_LISTED })],
    [
      "a missing file inside the vault directory",
      () => ({
        listedDirs: [join(tempDir, "vault")],
        path: join(tempDir, "vault", "missing.db"),
        message: NOT_LISTED,
      }),
    ],
    [
      "a file of a bare repository in a listed directory",
      () => ({
        listedDirs: [listed],
        path: join(listed, "bare.git", "config"),
        message: NOT_LISTED,
      }),
    ],
    [
      "a file through a link into a `.git`",
      () => ({
        listedDirs: [listed],
        path: join(listed, "to-dotgit", "config"),
        message: NOT_LISTED,
      }),
    ],
    [
      "a `.git` spelling",
      () => ({
        listedDirs: [listed],
        path: join(listed, "wt", ".git", "config"),
        message: NOT_LISTED,
      }),
    ],
  ];

  const WIN32_REFUSALS: readonly Refusal[] = [
    [
      `a device, ${B}${B}.${B}NUL,`,
      () => ({ listedDirs: [listed], path: `${B}${B}.${B}NUL`, message: DEVICE }),
    ],
    [
      "a network share, //server/share/f,",
      () => ({ listedDirs: [listed], path: "//server/share/f", message: SHARE }),
    ],
  ];

  const POSIX_REFUSALS: readonly Refusal[] = [
    ["a device, /dev/null,", () => ({ listedDirs: [listed], path: "/dev/null", message: DEVICE })],
  ];

  it.each(REFUSALS)(
    "refuses %s with one failed secret.use row, ATTACHMENT_REJECTED",
    refusesWithOneRow,
  );

  // Off win32 both spellings are ordinary paths, judged through the file system.
  it.runIf(WIN32).each(WIN32_REFUSALS)(
    "refuses %s with one failed secret.use row, ATTACHMENT_REJECTED (win32)",
    refusesWithOneRow,
  );

  // On win32 /dev/null is no absolute path.
  it.skipIf(WIN32).each(POSIX_REFUSALS)(
    "refuses %s with one failed secret.use row, ATTACHMENT_REJECTED (POSIX)",
    refusesWithOneRow,
  );

  it("after declareDaemon an attachment in a declared directory refuses with the list message and one failed row", async () => {
    const vault = await vaultListing(listed);
    vault.declareDaemon({ protectedDirs: [listed], protectedFiles: [] });
    await expectOneRefusal(vault, join(listed, "report.txt"), NOT_LISTED);
  });

  it.skipIf(process.platform === "win32")(
    "after declareDaemon an attachment in a 0775 listed directory refuses with the list message and one failed row, and passes once 0755 (POSIX modes)",
    async () => {
      chmodSync(listed, 0o775);
      const vault = await vaultListing(listed);
      vault.declareDaemon({ protectedDirs: [], protectedFiles: [] });
      await expectOneRefusal(vault, join(listed, "report.txt"), NOT_LISTED);
      chmodSync(listed, 0o755);
      await expectVaultError(
        () => vault.useSecret("secret://mail", send(join(listed, "report.txt"))),
        ErrorCode.SSRF_BLOCKED,
      );
    },
  );
});
