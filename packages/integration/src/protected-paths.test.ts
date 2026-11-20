import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo, Server } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { VaultEngine, controlledPathDirs, resolveExecutable } from "@harpoc/core";
import {
  AuditEventType,
  ErrorCode,
  SESSION_FILE_NAME,
  VAULT_DB_NAME,
  VaultError,
} from "@harpoc/shared";
import type { UseSecretAction } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { FIXTURE_CA_PEM, startFakeSmtp } from "./helpers/fake-smtp-server.js";
import type { FakeSmtp } from "./helpers/fake-smtp-server.js";
import { tierRequired } from "./helpers/platform-tiers.js";
import { resolveSupportedGit } from "./helpers/supported-git.js";

const NATIVE_SSH_DIR = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "OpenSSH");

// The sftp injector resolves the bare name against the process PATH, so the
// native OpenSSH directory has to lead it on win32 (as core's sftp suites set it).
if (process.platform === "win32") {
  process.env.PATH = [
    NATIVE_SSH_DIR,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== NATIVE_SSH_DIR.toLowerCase()),
  ].join(delimiter);
}

function nativeSftpClient(): string | null {
  const resolved = resolveExecutable("sftp", controlledPathDirs());
  if (resolved === null) return null;
  if (
    process.platform === "win32" &&
    dirname(resolved).toLowerCase() !== NATIVE_SSH_DIR.toLowerCase()
  ) {
    return null;
  }
  return resolved;
}

const SFTP = nativeSftpClient();
const GIT = resolveSupportedGit();

it("ssh-live tier: required legs fail instead of skipping when sftp or a supported git is unresolvable", () => {
  if ((SFTP === null || GIT === null) && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but sftp or a supported git is unresolvable',
    );
  }
});

const PASSWORD = "protected-paths-master-pw";
const HOST = "127.0.0.1";
const SSH_KEY_PEM = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
}).privateKey;

const MAIL_CREDENTIAL = "mailer:protected-paths-mail-value";

const GIT_CREDENTIAL = "x-access-token:protected-paths-git-value";
const IN_VAULT = "Attachment rejected: an attachment path is inside the vault directory";
const NOT_LISTED = "sftp local path is not inside a directory the secret's policy lists";
const GIT_PROTECTED = "git working directory is inside a directory the vault protects";

interface Target {
  key: string;
  fileLabel: string;
  dirLabel: string;
  dir: () => string;
  file: () => string;
}

let root = "";
let credentialsDir = "";
let runtimeDir = "";
let backupDir = "";
let backupCopy = "";
let ownDir = "";
let daemon: VaultEngine | undefined;
let plain: VaultEngine | undefined;
let listener: Server | undefined;
let listenerPort = 0;
let connections = 0;

const PROTECTED: readonly Target[] = [
  {
    key: "credentials",
    fileLabel: "the fake credentials directory's harpoc-unlock",
    dirLabel: "the fake credentials directory",
    dir: () => credentialsDir,
    file: () => join(credentialsDir, "harpoc-unlock"),
  },
  {
    key: "runtime",
    fileLabel: "the runtime directory's agent/token.jwt",
    dirLabel: "the runtime directory",
    dir: () => runtimeDir,
    file: () => join(runtimeDir, "agent", "token.jwt"),
  },
  {
    key: "backup",
    fileLabel: "the backup directory's copy",
    dirLabel: "the backup directory",
    dir: () => backupDir,
    file: () => backupCopy,
  },
];

const OWN: readonly Target[] = [
  {
    key: "own",
    fileLabel: "a file in a directory of the vault user's own beside them",
    dirLabel: "a directory of the vault user's own beside them",
    dir: () => ownDir,
    file: () => join(ownDir, "report.txt"),
  },
];

const files = (targets: readonly Target[]) => targets.map((t) => [t.fileLabel, t] as const);
const dirs = (targets: readonly Target[]) => targets.map((t) => [t.dirLabel, t] as const);

function fixtureDir(path: string, mode: number): string {
  mkdirSync(path, { mode });
  chmodSync(path, mode);
  return path;
}

function fixtureFile(path: string, bytes: Buffer, mode: number): void {
  writeFileSync(path, bytes, { mode });
  chmodSync(path, mode);
}

beforeAll(async () => {
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-protected-paths-")));
  chmodSync(root, 0o700);
  const vaultDir = fixtureDir(join(root, "vault"), 0o700);
  credentialsDir = fixtureDir(join(root, "credentials"), 0o700);
  fixtureFile(join(credentialsDir, "harpoc-unlock"), randomBytes(32), 0o400);
  runtimeDir = fixtureDir(join(root, "run"), 0o755);
  fixtureDir(join(runtimeDir, "agent"), 0o700);
  fixtureFile(join(runtimeDir, "agent", "token.jwt"), randomBytes(96), 0o600);
  backupDir = fixtureDir(join(root, "backups"), 0o700);
  ownDir = fixtureDir(join(root, "reports"), 0o755);
  fixtureFile(join(ownDir, "report.txt"), Buffer.from("quarterly report"), 0o644);

  const dbPath = join(vaultDir, VAULT_DB_NAME);
  const sessionPath = join(vaultDir, SESSION_FILE_NAME);
  daemon = new VaultEngine({ dbPath, sessionPath });
  await daemon.initVault(PASSWORD);
  plain = new VaultEngine({ dbPath, sessionPath });
  await plain.loadSession();
  backupCopy = (await plain.backupToDirectory(backupDir, { keep: 1, label: "--backup-dir" })).file;
  daemon.declareDaemon({
    protectedDirs: [credentialsDir, runtimeDir, backupDir],
    protectedFiles: [],
  });

  const server = createServer((socket) => {
    connections++;
    socket.destroy();
  });
  listener = server;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, HOST, resolve);
  });
  listenerPort = (server.address() as AddressInfo).port;
}, 180_000);

afterAll(async () => {
  try {
    if (listener !== undefined) {
      const server = listener;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await plain?.destroy();
    await daemon?.destroy();
  } finally {
    if (root !== "") {
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
});

beforeEach(() => {
  connections = 0;
});

async function useRows(
  engine: VaultEngine,
  handle: string,
): Promise<ReturnType<VaultEngine["queryAudit"]>> {
  const secretId = await engine.resolveSecretId(handle);
  return engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
}

async function codeOf(
  engine: VaultEngine,
  handle: string,
  action: UseSecretAction,
): Promise<string | undefined> {
  try {
    await engine.useSecret(handle, action);
    return undefined;
  } catch (err) {
    if (!(err instanceof VaultError)) throw err;
    return err.code;
  }
}

function upload(localPath: string): UseSecretAction {
  return {
    type: "sftp",
    host: HOST,
    port: listenerPort,
    user: "deploy",
    operation: "upload",
    remote_path: "/srv/upload.bin",
    local_path: localPath,
    timeout_ms: 20_000,
  };
}

function clone(destination: string): UseSecretAction {
  return {
    type: "git",
    operation: "clone",
    repository: `http://${HOST}:${String(listenerPort)}/repo.git`,
    working_directory: destination,
    timeout_ms: 20_000,
  };
}

async function sftpSecret(engine: VaultEngine, name: string): Promise<string> {
  const { handle } = await engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(SSH_KEY_PEM)),
  });
  await engine.setInjectionPolicy(handle, {
    host_allowlist: [HOST],
    command_allowlist: [SFTP as string],
    local_dirs: [root],
  });
  await engine.setConnectionConfig(handle, {
    ssh: { known_hosts: [`${HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
  });
  return handle;
}

async function mailSecret(engine: VaultEngine, name: string, port: number): Promise<string> {
  const { handle } = await engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(MAIL_CREDENTIAL)),
  });
  await engine.setInjectionPolicy(handle, {
    host_allowlist: [`${HOST}:${String(port)}`],
    smtp_recipient_allowlist: ["*@example.com"],
    local_dirs: [root],
  });
  await engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });
  return handle;
}

async function gitSecret(engine: VaultEngine, name: string): Promise<string> {
  const { handle } = await engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(GIT_CREDENTIAL)),
  });
  await engine.setInjectionPolicy(handle, {
    command_allowlist: [GIT as string],
    url_allowlist: [`http://${HOST}:${String(listenerPort)}/*`],
  });
  return handle;
}

async function sftpRefused(engine: VaultEngine, name: string, target: Target): Promise<void> {
  const handle = await sftpSecret(engine, name);
  const err = await expectVaultError(
    () => engine.useSecret(handle, upload(target.file())),
    ErrorCode.LOCAL_PATH_NOT_ALLOWED,
  );
  expect(err.message).toBe(NOT_LISTED);
  const rows = await useRows(engine, handle);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.success).toBe(false);
  expect(rows[0]?.detail).toMatchObject({
    context: "sftp",
    operation: "upload",
    error: ErrorCode.LOCAL_PATH_NOT_ALLOWED,
  });
  expect(connections).toBe(0);
}

async function sftpNotRefused(engine: VaultEngine, name: string, target: Target): Promise<void> {
  const handle = await sftpSecret(engine, name);
  const code = await codeOf(engine, handle, upload(target.file()));
  expect(code).toBeDefined();
  expect(code).not.toBe(ErrorCode.LOCAL_PATH_NOT_ALLOWED);
  expect(connections).toBeGreaterThan(0);
  const rows = await useRows(engine, handle);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.detail).toMatchObject({ context: "sftp", operation: "upload", error: code });
}

async function gitRefused(engine: VaultEngine, name: string, destination: string): Promise<void> {
  const handle = await gitSecret(engine, name);
  const err = await expectVaultError(
    () => engine.useSecret(handle, clone(destination)),
    ErrorCode.LOCAL_PATH_NOT_ALLOWED,
  );
  expect(err.message).toBe(GIT_PROTECTED);
  const rows = await useRows(engine, handle);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.success).toBe(false);
  expect(rows[0]?.detail).toEqual({
    context: "git",
    operation: "clone",
    error: ErrorCode.LOCAL_PATH_NOT_ALLOWED,
  });
  expect(JSON.stringify(rows).includes(JSON.stringify(root).slice(1, -1))).toBe(false);
  expect(connections).toBe(0);
}

async function gitNotRefused(engine: VaultEngine, name: string, target: Target): Promise<void> {
  const handle = await gitSecret(engine, name);
  const code = await codeOf(engine, handle, clone(join(target.dir(), "clone")));
  expect(code).not.toBe(ErrorCode.LOCAL_PATH_NOT_ALLOWED);
  expect(connections).toBeGreaterThan(0);
  const rows = await useRows(engine, handle);
  expect(rows).toHaveLength(1);
  expect(rows[0]?.detail?.["error"]).not.toBe(ErrorCode.LOCAL_PATH_NOT_ALLOWED);
}

describe("smtp attachments", () => {
  let smtp: FakeSmtp;

  beforeEach(async () => {
    smtp = await startFakeSmtp({
      starttls: false,
      implicitTls: true,
      authMechanisms: ["PLAIN"],
      auth: "ok",
      rcpt: "ok",
    });
  });

  afterEach(async () => {
    await smtp.close();
  });

  function send(path: string): UseSecretAction {
    return {
      type: "smtp",
      host: HOST,
      port: smtp.port,
      security: "tls",
      from: "agent@harpoc.local",
      to: ["ops@example.com"],
      subject: "protected paths",
      text: "attached",
      attachments: [{ path }],
    };
  }

  async function refused(engine: VaultEngine, name: string, target: Target): Promise<void> {
    const handle = await mailSecret(engine, name, smtp.port);
    const err = await expectVaultError(
      () => engine.useSecret(handle, send(target.file())),
      ErrorCode.ATTACHMENT_REJECTED,
    );
    expect(err.message).toBe(IN_VAULT);
    const rows = await useRows(engine, handle);
    expect(rows.map(({ success, detail }) => ({ success, detail }))).toEqual([
      {
        success: false,
        detail: {
          context: "smtp",
          host: HOST,
          from: "agent@harpoc.local",
          recipients: ["ops@example.com"],
          attachment_paths: [target.file()],
          attachment_total_bytes: 0,
          error: ErrorCode.ATTACHMENT_REJECTED,
        },
      },
    ]);
    const wire = smtp.wire();
    expect(wire.plaintext.length + wire.postTls.length).toBe(0);
  }

  async function sent(engine: VaultEngine, name: string, target: Target): Promise<void> {
    const handle = await mailSecret(engine, name, smtp.port);
    const res = await engine.useSecret(handle, send(target.file()));
    expect(res).toMatchObject({ type: "smtp", accepted: 1 });
    const rows = await useRows(engine, handle);
    expect(rows.map(({ success, detail }) => ({ success, detail }))).toEqual([
      {
        success: true,
        detail: {
          context: "smtp",
          host: HOST,
          from: "agent@harpoc.local",
          recipients: ["ops@example.com"],
          attachment_paths: [target.file()],
          attachment_total_bytes: statSync(target.file()).size,
        },
      },
    ]);
  }

  describe("with the engine declared a daemon", () => {
    it.each(files(PROTECTED))(
      "an attachment of %s is refused ATTACHMENT_REJECTED with the in-vault message and one failed secret.use row, nothing connected",
      (_label, target) => refused(daemon as VaultEngine, `smtp-${target.key}-daemon`, target),
    );

    it.each(files(OWN))(
      "an attachment of %s is sent: the walk passes the fixture's directories",
      (_label, target) => sent(daemon as VaultEngine, `smtp-${target.key}-daemon`, target),
    );
  });

  describe("without the declaration", () => {
    it.each(files(PROTECTED))("an attachment of %s is read and sent", (_label, target) =>
      sent(plain as VaultEngine, `smtp-${target.key}-plain`, target),
    );
  });
});

describe.skipIf(SFTP === null)(
  "sftp uploads (skipped where no native sftp client resolves)",
  () => {
    describe("with the engine declared a daemon", () => {
      it.each(files(PROTECTED))(
        "an upload of %s is refused LOCAL_PATH_NOT_ALLOWED with one failed secret.use row, nothing connected",
        (_label, target) => sftpRefused(daemon as VaultEngine, `sftp-${target.key}-daemon`, target),
      );

      it.each(files(OWN))(
        "an upload of %s goes on to the connection: the walk passes the fixture's directories",
        (_label, target) =>
          sftpNotRefused(daemon as VaultEngine, `sftp-${target.key}-daemon`, target),
      );
    });

    describe("without the declaration", () => {
      it.each(files(PROTECTED))(
        "an upload of %s is not refused for the path and goes on to the connection",
        (_label, target) =>
          sftpNotRefused(plain as VaultEngine, `sftp-${target.key}-plain`, target),
      );
    });
  },
);

describe.skipIf(GIT === null)("git clones (skipped where no supported git resolves)", () => {
  describe("with the engine declared a daemon", () => {
    it.each(dirs(PROTECTED))(
      "a clone into %s is refused LOCAL_PATH_NOT_ALLOWED with one failed secret.use row naming no path, nothing connected",
      (_label, target) =>
        gitRefused(daemon as VaultEngine, `git-${target.key}-daemon`, join(target.dir(), "clone")),
    );

    // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
    // `..` behind a link from the link's target.
    it.skipIf(process.platform === "win32")(
      "a clone spelled through a link into the vault's directory and `..` into the backup directory is refused LOCAL_PATH_NOT_ALLOWED with one failed secret.use row naming no path, nothing written, nothing connected",
      async () => {
        const work = fixtureDir(join(root, "agent-work"), 0o755);
        const link = join(work, "to-vault");
        symlinkSync(join(root, "vault"), link, "dir");
        const held = readdirSync(backupDir);
        try {
          await gitRefused(
            daemon as VaultEngine,
            "git-link-parent-daemon",
            `${link}/../backups/planted`,
          );
          expect(readdirSync(backupDir)).toEqual(held);
          expect(readdirSync(work)).toEqual(["to-vault"]);
        } finally {
          rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        }
      },
    );

    it.each(dirs(OWN))("a clone into %s goes on to its network step", (_label, target) =>
      gitNotRefused(daemon as VaultEngine, `git-${target.key}-daemon`, target),
    );
  });

  describe("with the engine declared a daemon whose working directory holds an empty backup directory", () => {
    let started: VaultEngine | undefined;
    let cwd: MockInstance<typeof process.cwd> | undefined;

    afterEach(async () => {
      cwd?.mockRestore();
      cwd = undefined;
      await started?.destroy();
      started = undefined;
    });

    it("a clone of a repository of that directory's name without a working directory is refused INVALID_GIT_CONFIG with one failed secret.use row naming no path, nothing written, nothing connected", async () => {
      const work = fixtureDir(join(root, "daemon-cwd"), 0o700);
      const emptyBackups = fixtureDir(join(work, "backups"), 0o700);
      const engine = new VaultEngine({
        dbPath: join(root, "vault", VAULT_DB_NAME),
        sessionPath: join(root, "vault", SESSION_FILE_NAME),
      });
      started = engine;
      await engine.loadSession();
      engine.declareDaemon({ protectedDirs: [emptyBackups], protectedFiles: [] });
      const handle = await gitSecret(engine, "git-clone-no-directory-daemon");
      cwd = vi.spyOn(process, "cwd").mockReturnValue(work);

      const err = await expectVaultError(
        () =>
          engine.useSecret(handle, {
            type: "git",
            operation: "clone",
            repository: `http://${HOST}:${String(listenerPort)}/backups.git`,
            timeout_ms: 20_000,
          }),
        ErrorCode.INVALID_GIT_CONFIG,
      );

      expect(err.message).toBe("working_directory is required for clone in a daemon");
      const rows = await useRows(engine, handle);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.success).toBe(false);
      expect(rows[0]?.detail).toEqual({
        context: "git",
        operation: "clone",
        error: ErrorCode.INVALID_GIT_CONFIG,
      });
      expect(JSON.stringify(rows).includes(JSON.stringify(root).slice(1, -1))).toBe(false);
      expect(readdirSync(emptyBackups)).toEqual([]);
      expect(readdirSync(work)).toEqual(["backups"]);
      expect(connections).toBe(0);
    });
  });

  describe("without the declaration", () => {
    it.each(dirs(PROTECTED))(
      "a clone into %s is not refused for the path and goes on to its network step",
      (_label, target) => gitNotRefused(plain as VaultEngine, `git-${target.key}-plain`, target),
    );
  });
});
