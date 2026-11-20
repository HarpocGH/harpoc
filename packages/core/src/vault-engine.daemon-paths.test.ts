import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SftpAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { controlledPathDirs } from "./injection/allowlist.js";
import { resolveNativeSshClient } from "./injection/__fixtures__/native-ssh-client.js";
import { tierRequired } from "./injection/__fixtures__/platform-tier.js";
import { VaultEngine } from "./vault-engine.js";
import { system32Path } from "./win32-paths.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// The sftp injector resolves the bare name against the process PATH, so the
// native OpenSSH directory has to lead it on win32 (sftp-injector.spawn.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const SFTP = resolveNativeSshClient("sftp");

it("ssh-live tier: required legs fail instead of skipping when sftp is unresolvable", () => {
  if (SFTP === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no sftp client resolves',
    );
  }
});

const KEY_PEM = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
}).privateKey;

// Loopback port 1: the transfer fails at the connection, nothing leaves the host.
const HOST = "127.0.0.1";

let tempDir: string;
let listedDir: string;
let listedFile: string;
let engine: VaultEngine;

beforeEach(async () => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  tempDir = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-daemon-paths-")));
  listedDir = join(tempDir, "listed");
  listedFile = join(listedDir, "report.pdf");
  for (const dir of ["vault", "session", "listed", "other"]) mkdirSync(join(tempDir, dir));
  if (process.platform !== "win32") chmodSync(listedDir, 0o755);
  writeFileSync(listedFile, "report");
  engine = new VaultEngine({
    dbPath: join(tempDir, "vault", "test.vault.db"),
    sessionPath: join(tempDir, "session", "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
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
    command_allowlist: [SFTP as string],
    local_dirs: localDirs,
  });
  await engine.setConnectionConfig(handle, {
    ssh: { known_hosts: [`${HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
  });
  return handle;
}

function upload(localPath: string): SftpAction {
  return {
    type: "sftp",
    host: HOST,
    port: 1,
    user: "deploy",
    operation: "upload",
    remote_path: "/srv/report.pdf",
    local_path: localPath,
  };
}

async function useRows(handle: string): Promise<ReturnType<VaultEngine["queryAudit"]>> {
  const secretId = await engine.resolveSecretId(handle);
  return engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
}

async function codePastTheJudgement(handle: string, localPath: string): Promise<string> {
  let thrown: unknown;
  try {
    await engine.useSecret(handle, upload(localPath));
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(VaultError);
  const { code } = thrown as VaultError;
  expect(code).not.toBe(ErrorCode.LOCAL_PATH_NOT_ALLOWED);
  return code;
}

describe.skipIf(SFTP === null)("VaultEngine.declareDaemon: the sftp context's daemon paths", () => {
  it.skipIf(process.platform === "win32")(
    "before declareDaemon an upload from a 0775 listed directory passes the judgement (POSIX modes)",
    async () => {
      const dir = join(tempDir, "group-writable");
      mkdirSync(dir);
      chmodSync(dir, 0o775);
      writeFileSync(join(dir, "report.pdf"), "report");
      const handle = await sftpSecret([dir]);
      const code = await codePastTheJudgement(handle, join(dir, "report.pdf"));
      const rows = await useRows(handle);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.detail).toMatchObject({ context: "sftp", operation: "upload", error: code });
    },
  );

  it("after declareDaemon an upload that names a file in a declared directory writes one failed secret.use row with LOCAL_PATH_NOT_ALLOWED", async () => {
    const handle = await sftpSecret([listedDir]);
    engine.declareDaemon({ protectedDirs: [listedDir], protectedFiles: [] });
    await expectVaultError(
      () => engine.useSecret(handle, upload(listedFile)),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
    const rows = await useRows(handle);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toMatchObject({
      context: "sftp",
      operation: "upload",
      error: ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    });
  });

  it("declareDaemon keeps a copy: emptying the arrays it was handed changes nothing", async () => {
    const handle = await sftpSecret([listedDir]);
    const protectedDirs = [listedDir];
    const protectedFiles = [join(tempDir, "other", "key")];
    engine.declareDaemon({ protectedDirs, protectedFiles });
    protectedDirs.length = 0;
    protectedFiles.length = 0;
    await expectVaultError(
      () => engine.useSecret(handle, upload(listedFile)),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
    const rows = await useRows(handle);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toMatchObject({
      context: "sftp",
      operation: "upload",
      error: ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    });
  });

  it("a second declareDaemon replaces the first", async () => {
    const handle = await sftpSecret([listedDir]);
    engine.declareDaemon({ protectedDirs: [listedDir], protectedFiles: [] });
    await expectVaultError(
      () => engine.useSecret(handle, upload(listedFile)),
      ErrorCode.LOCAL_PATH_NOT_ALLOWED,
    );
    engine.declareDaemon({ protectedDirs: [join(tempDir, "other")], protectedFiles: [] });
    await codePastTheJudgement(handle, listedFile);
  });
});
