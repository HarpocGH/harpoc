import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SftpAction } from "@harpoc/shared";
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
const REMOTE = "dir\\file";

const spawnMock = vi.mocked(spawnCaptured);

let tempDir: string;
let listedFile: string;
let savedPath: string | undefined;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-sftp-remote-engine-")));
  const listedDir = join(tempDir, "listed");
  listedFile = join(listedDir, "report.pdf");
  const binDir = join(tempDir, "bin");
  for (const dir of ["vault", "session", "listed", "bin"]) mkdirSync(join(tempDir, dir));
  writeFileSync(listedFile, "report");
  const sftpPath = join(binDir, process.platform === "win32" ? "sftp.exe" : "sftp");
  writeFileSync(sftpPath, "", { mode: 0o755 });
  savedPath = process.env.PATH;
  process.env.PATH = binDir + delimiter + (savedPath ?? "");
  spawnMock.mockReset();
  spawnMock.mockResolvedValue(OK_RESULT);
  engine = new VaultEngine({
    dbPath: join(tempDir, "vault", "test.vault.db"),
    sessionPath: join(tempDir, "session", "session.json"),
  });
  await engine.initVault("password");
  await engine.createSecret({
    name: "deploy-key",
    type: "api_key",
    value: new Uint8Array(Buffer.from(KEY_PEM)),
  });
  await engine.setInjectionPolicy("secret://deploy-key", {
    host_allowlist: [HOST],
    command_allowlist: [sftpPath],
    local_dirs: [listedDir],
  });
  await engine.setConnectionConfig("secret://deploy-key", {
    ssh: { known_hosts: [`${HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
  });
});

afterEach(async () => {
  if (savedPath === undefined) delete process.env.PATH;
  else process.env.PATH = savedPath;
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("VaultEngine sftp: a backslash in the remote path of a transfer", () => {
  it.each(["upload", "download"] as const)(
    "%s: refused INVALID_INPUT with one failed row that names the remote path as sent",
    async (operation) => {
      const action: SftpAction = {
        type: "sftp",
        host: HOST,
        user: "deploy",
        operation,
        remote_path: REMOTE,
        local_path: listedFile,
      };
      const err = await expectVaultError(
        () => engine.useSecret("secret://deploy-key", action),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe("sftp remote path must not contain a backslash");
      expect(spawnMock).not.toHaveBeenCalled();
      const secretId = await engine.resolveSecretId("secret://deploy-key");
      const rows = engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.success).toBe(false);
      expect(rows[0]?.detail).toStrictEqual({
        context: "sftp",
        host: HOST,
        operation,
        port: null,
        remote_path: REMOTE,
        local_path: listedFile,
        network_isolation: false,
        fs_isolation: false,
        error: ErrorCode.INVALID_INPUT,
      });
    },
  );
});
