import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import { controlledPathDirs, resolveExecutable } from "./injection/allowlist.js";
import { resolveNativeSshClient } from "./injection/__fixtures__/native-ssh-client.js";
import { forceJobWrapperUnavailableForTests } from "./injection/win32-job-wrapper.js";
import { system32Path } from "./win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// The ssh and sftp injectors resolve the bare name against the process PATH, so
// the native OpenSSH directory has to lead it on win32 (ssh-injector.spawn.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

// The refusal comes after allowlist resolution, so each context needs its binary;
// a host without one skips that context's case.
const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");
const SFTP = resolveNativeSshClient("sftp");
const DOCKER = resolveExecutable("docker", controlledPathDirs());

const REASON = "test: no job wrapper on this host";

let tempDir: string;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-ste-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  forceJobWrapperUnavailableForTests(REASON);
});

afterEach(async () => {
  forceJobWrapperUnavailableForTests(null);
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

type Policy = Parameters<VaultEngine["setInjectionPolicy"]>[1];
type Action = Parameters<VaultEngine["useSecret"]>[1];

function sshKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
}

async function strictSecret(name: string, value: string, policy: Policy): Promise<string> {
  await engine.createSecret({ name, type: "api_key", value: new Uint8Array(Buffer.from(value)) });
  const handle = `secret://${name}`;
  await engine.setInjectionPolicy(
    handle,
    { ...policy, strict_tree_exit: true },
    { acknowledge_interpreters: true },
  );
  return handle;
}

async function refusedRow(handle: string, action: Action): Promise<unknown> {
  const err = await expectVaultError(
    () => engine.useSecret(handle, action),
    ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
  );
  expect(err.message).toContain(REASON);
  const secretId = await engine.resolveSecretId(handle);
  const rows = engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
  expect(rows).toHaveLength(1);
  expect(rows[0]?.success).toBe(false);
  return rows[0]?.detail;
}

// M-P2-21 (test-review-2026-10-09): win32-only by design (getting-started.md:283)
// — POSIX runs a strict spawn without a wrapper (spawn-captured.job.test.ts).
// The targets are loopback port 1 or `localhost:5999`, so nothing leaves the host.
describe.skipIf(process.platform !== "win32")(
  "strict_tree_exit with the job wrapper unavailable is refused before any spawn, audited (M-P2-21)",
  () => {
    it("process", async () => {
      const handle = await strictSecret("ste-process", "ste-process-value", {
        command_allowlist: [process.execPath],
      });
      const detail = await refusedRow(handle, {
        type: "process",
        command: process.execPath,
        args: ["-e", "process.exit(0)"],
        env_var: "TOKEN",
      });
      expect(detail).toMatchObject({
        context: "process",
        error: ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
      });
    });

    it.skipIf(GIT === null)("git (https)", async () => {
      const handle = await strictSecret("ste-git", "x-access-token:ste-git-value", {
        command_allowlist: ["git"],
        url_allowlist: ["https://127.0.0.1:1/*"],
      });
      const detail = await refusedRow(handle, {
        type: "git",
        operation: "clone",
        repository: "https://127.0.0.1:1/harpoc/u3.git",
        working_directory: join(tempDir, "clone"),
      });
      expect(detail).toMatchObject({
        context: "git",
        transport: "https",
        error: ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
      });
    });

    it.skipIf(SSH === null)("ssh", async () => {
      const handle = await strictSecret("ste-ssh", sshKeyPem(), {
        command_allowlist: ["ssh"],
        host_allowlist: ["127.0.0.1"],
      });
      await engine.setConnectionConfig(handle, {
        ssh: { known_hosts: ["127.0.0.1 ssh-ed25519 AAAA"] },
      });
      const detail = await refusedRow(handle, {
        type: "ssh",
        host: "127.0.0.1",
        port: 1,
        user: "deploy",
        command: "true",
      });
      expect(detail).toMatchObject({
        context: "ssh",
        error: ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
      });
    });

    it.skipIf(SFTP === null)("sftp", async () => {
      const handle = await strictSecret("ste-sftp", sshKeyPem(), {
        command_allowlist: ["sftp"],
        host_allowlist: ["127.0.0.1"],
      });
      await engine.setConnectionConfig(handle, {
        ssh: { known_hosts: ["127.0.0.1 ssh-ed25519 AAAA"] },
      });
      const detail = await refusedRow(handle, {
        type: "sftp",
        host: "127.0.0.1",
        port: 1,
        user: "deploy",
        operation: "list",
        remote_path: "/srv",
      });
      expect(detail).toMatchObject({
        context: "sftp",
        host: "127.0.0.1",
        error: ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
      });
    });

    it.skipIf(DOCKER === null)("docker_registry", async () => {
      const handle = await strictSecret("ste-docker", "ste-user:ste-docker-value", {
        command_allowlist: ["docker"],
        host_allowlist: ["localhost:5999"],
      });
      const detail = await refusedRow(handle, {
        type: "docker_registry",
        operation: "pull",
        image: "localhost:5999/harpoc/u3:1",
        timeout_ms: 30_000,
      });
      expect(detail).toMatchObject({
        context: "docker_registry",
        error: ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
      });
    });
  },
);
