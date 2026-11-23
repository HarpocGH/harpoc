import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SftpAction, VaultError } from "@harpoc/shared";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { spawnCaptured } from "./injection/spawn-captured.js";
import type { SpawnCapturedResult } from "./injection/spawn-captured.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);
vi.mock("./injection/spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const KEY_PEM = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
}).privateKey;

const HOST = "deploy.example.com";

const spawnMock = vi.mocked(spawnCaptured);

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let listedDir: string;
let sftpPath: string;
let savedPath: string | undefined;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-sftp-local-engine-")));
  dbPath = join(tempDir, "vault", "test.vault.db");
  sessionPath = join(tempDir, "session", "session.json");
  listedDir = join(tempDir, "listed");
  const binDir = join(tempDir, "bin");
  for (const dir of [dirname(dbPath), dirname(sessionPath), listedDir, binDir]) mkdirSync(dir);
  writeFileSync(join(listedDir, "report.pdf"), "report");
  sftpPath = join(binDir, process.platform === "win32" ? "sftp.exe" : "sftp");
  writeFileSync(sftpPath, "", { mode: 0o755 });
  savedPath = process.env.PATH;
  process.env.PATH = binDir + delimiter + (savedPath ?? "");
  spawnMock.mockReset();
  spawnMock.mockResolvedValue(OK_RESULT);
  engine = new VaultEngine({ dbPath, sessionPath });
  await engine.initVault("password");
});

afterEach(async () => {
  if (savedPath === undefined) delete process.env.PATH;
  else process.env.PATH = savedPath;
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function sftpSecret(localDirs: string[]): Promise<string> {
  await engine.createSecret({
    name: "deploy-key",
    type: "api_key",
    value: new Uint8Array(Buffer.from(KEY_PEM)),
  });
  const handle = "secret://deploy-key";
  await engine.setInjectionPolicy(handle, {
    host_allowlist: [HOST],
    command_allowlist: [sftpPath],
    local_dirs: localDirs,
  });
  await engine.setConnectionConfig(handle, {
    ssh: { known_hosts: [`${HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
  });
  return handle;
}

function transfer(operation: "upload" | "download", localPath: string): SftpAction {
  return {
    type: "sftp",
    host: HOST,
    user: "deploy",
    operation,
    remote_path: "/srv/report.pdf",
    local_path: localPath,
  };
}

async function refusedUse(
  handle: string,
  action: SftpAction,
  code: ErrorCode = ErrorCode.LOCAL_PATH_NOT_ALLOWED,
): Promise<{ error: VaultError; detail: unknown }> {
  const error = await expectVaultError(() => engine.useSecret(handle, action), code);
  const secretId = await engine.resolveSecretId(handle);
  const rows = engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
  expect(rows).toHaveLength(1);
  expect(rows[0]?.success).toBe(false);
  expect(spawnMock).not.toHaveBeenCalled();
  return { error, detail: rows[0]?.detail };
}

async function refusedUseRow(
  handle: string,
  action: SftpAction,
  code: ErrorCode = ErrorCode.LOCAL_PATH_NOT_ALLOWED,
): Promise<unknown> {
  return (await refusedUse(handle, action, code)).detail;
}

describe("VaultEngine sftp: the local path is judged against the policy's directories", () => {
  it("an upload of the vault database is refused with one failed row", async () => {
    const handle = await sftpSecret([dirname(dbPath)]);
    const detail = await refusedUseRow(handle, transfer("upload", dbPath));
    expect(detail).toMatchObject({
      context: "sftp",
      operation: "upload",
      error: "LOCAL_PATH_NOT_ALLOWED",
      network_isolation: false,
      fs_isolation: false,
    });
  });

  it("a download onto the session file is refused with one failed row", async () => {
    const handle = await sftpSecret([dirname(sessionPath)]);
    const detail = await refusedUseRow(handle, transfer("download", sessionPath));
    expect(detail).toMatchObject({
      context: "sftp",
      operation: "download",
      error: "LOCAL_PATH_NOT_ALLOWED",
      network_isolation: false,
      fs_isolation: false,
    });
  });

  it("a batch line longer than sftp's line buffer is refused with one failed row", async () => {
    const handle = await sftpSecret([listedDir]);
    const action = {
      ...transfer("download", join(listedDir, "report.pdf")),
      remote_path: `/srv/${"r".repeat(2048)}`,
    };
    const detail = await refusedUseRow(handle, action, ErrorCode.INVALID_INPUT);
    expect(detail).toMatchObject({
      context: "sftp",
      operation: "download",
      error: "INVALID_INPUT",
      network_isolation: false,
      fs_isolation: false,
    });
  });

  it("a transfer inside a listed directory reaches the spawn", async () => {
    const handle = await sftpSecret([listedDir]);
    await engine.useSecret(handle, transfer("upload", join(listedDir, "report.pdf")));
    expect(spawnMock).toHaveBeenCalledOnce();
  });

  it("the audit chain verifies after the refusals", async () => {
    const handle = await sftpSecret([dirname(dbPath), dirname(sessionPath)]);
    for (const action of [transfer("upload", dbPath), transfer("download", sessionPath)]) {
      await expectVaultError(
        () => engine.useSecret(handle, action),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
    }
    expect(engine.verifyAuditChain().valid).toBe(true);
  });
});

function gitDirectory(dir: string): void {
  mkdirSync(join(dir, "objects"), { recursive: true });
  mkdirSync(join(dir, "refs"));
  writeFileSync(join(dir, "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, "config"), "[core]\n");
}

describe("VaultEngine sftp: a git directory is answered as a path in no listed directory", () => {
  const NOT_LISTED_ERROR = {
    code: ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    statusCode: 403,
    message: "sftp local path is not inside a directory the secret's policy lists",
    details: undefined,
  };

  beforeEach(() => {
    gitDirectory(join(listedDir, "bare.git"));
    gitDirectory(join(listedDir, "wt", ".git"));
    writeFileSync(join(listedDir, "wt", "report.pdf"), "report");
    mkdirSync(join(tempDir, "outside"));
    writeFileSync(join(tempDir, "outside", "report.pdf"), "report");
    symlinkSync(join(listedDir, "bare.git"), join(listedDir, "to-bare"), "junction");
    symlinkSync(join(tempDir, "outside"), join(listedDir, "to-outside"), "junction");
  });

  function refusedRow(
    operation: "upload" | "download",
    localPath: string,
    error: string,
  ): Record<string, unknown> {
    return {
      context: "sftp",
      host: HOST,
      operation,
      port: null,
      remote_path: "/srv/report.pdf",
      local_path: localPath,
      network_isolation: false,
      fs_isolation: false,
      error,
    };
  }

  it.each([
    ["an upload through a link into a bare repository", "upload", ["to-bare", "config"]],
    ["a download through a link to the outside", "download", ["to-outside", "report.pdf"]],
  ] as const)(
    "%s: the error of a path in no listed directory and one failed row",
    async (_label, operation, names) => {
      const handle = await sftpSecret([listedDir]);
      const localPath = join(listedDir, ...names);
      const { error, detail } = await refusedUse(handle, transfer(operation, localPath));
      const { code, statusCode, message, details } = error;
      expect({ code, statusCode, message, details }).toEqual(NOT_LISTED_ERROR);
      expect(detail).toEqual(refusedRow(operation, localPath, "LOCAL_PATH_NOT_ALLOWED"));
    },
  );

  it("a `.git` spelling", async () => {
    const handle = await sftpSecret([listedDir]);
    const localPath = join(listedDir, "wt", ".git", "config");
    const { error, detail } = await refusedUse(
      handle,
      transfer("download", localPath),
      ErrorCode.INVALID_INPUT,
    );
    expect(error.message).toBe("sftp local path must not hold a .git segment");
    expect(detail).toEqual(refusedRow("download", localPath, "INVALID_INPUT"));
  });

  it("a work tree's file beside its `.git` reaches the spawn", async () => {
    const handle = await sftpSecret([listedDir]);
    await engine.useSecret(handle, transfer("upload", join(listedDir, "wt", "report.pdf")));
    expect(spawnMock).toHaveBeenCalledOnce();
  });
});
