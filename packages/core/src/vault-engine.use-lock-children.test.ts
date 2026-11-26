import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicyInput, UseSecretAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretStatus } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { readSshFixture } from "./injection/__fixtures__/agent-client.js";
import { resolveNativeSshClient } from "./injection/__fixtures__/native-ssh-client.js";
import { untilWritten } from "./injection/__fixtures__/spawn-children.js";
import { B0, BLOCK, BOOT } from "./injection/__fixtures__/ssh-public-keys.js";
import { resolveSupportedGit } from "./injection/__fixtures__/supported-git.js";
import { controlledPathDirs, resolveExecutable } from "./injection/allowlist.js";
import { spawnCaptured } from "./injection/spawn-captured.js";
import type { SpawnCapturedResult } from "./injection/spawn-captured.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import type { SshBootstrapSeam } from "./vault-engine.js";
import { VaultEngine } from "./vault-engine.js";
import { system32Path } from "./win32-paths.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);
vi.mock("./injection/spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

const actual = await vi.importActual<typeof import("./injection/spawn-captured.js")>(
  "./injection/spawn-captured.js",
);
const spawnMock = vi.mocked(spawnCaptured);

// The ssh and sftp injectors resolve the bare name against the process PATH, so
// the native OpenSSH directory has to lead it on win32 (ssh-injector.spawn.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

// Each context resolves its binary before the spawn; a host without one skips that context's row.
const SSH = resolveNativeSshClient("ssh");
const SFTP = resolveNativeSshClient("sftp");
const GIT = resolveSupportedGit();
const DOCKER = resolveExecutable("docker", controlledPathDirs());
const SSH_ON_PATH = resolveExecutable("ssh", controlledPathDirs());

const NODE = process.execPath;
const ENV: Record<string, string> = {
  PATH: process.env.PATH ?? process.env.Path ?? "",
  ...(process.platform === "win32" && process.env.SystemRoot
    ? { SystemRoot: process.env.SystemRoot }
    : {}),
};

// These rows spawn real children; the engine-building hooks ran past core's 30 s on loaded
// windows-latest legs (vault-engine.sftp-render-seal.test.ts).
const HOOK_TIMEOUT_MS = 120_000;
const ROW_TIMEOUT_MS = 60_000;
/** Beyond every budget of this file: a child alive after the wipe was not ended by it. */
const HOLD_MS = 120_000;
const MARKER_BOUND_MS = 15_000;
const GONE_TIMEOUT_MS = 15_000;

const HANDLE = "secret://k";

const KILLED: SpawnCapturedResult = {
  exit_code: null,
  stdout: "",
  stderr: "",
  timed_out: true,
  truncated: false,
  signal: "SIGKILL",
  spawn_failed: false,
  redacted: false,
};
const EXITED: SpawnCapturedResult = { ...KILLED, exit_code: 0, timed_out: false, signal: null };

interface EngineInternals {
  store: SqliteStore;
  sshBootstrap: SshBootstrapSeam;
  sealExpired(): void;
}

let tempDir: string;
let cloneDir: string;
let engine: VaultEngine;
let secretId: string;
/** A pid a row has read and not yet seen gone. */
let survivor: number | undefined;
let pending: Promise<unknown> | undefined;

const at = (): EngineInternals => engine as unknown as EngineInternals;

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw err;
  }
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

function quiet<T>(promise: Promise<T>): Promise<T> {
  promise.catch(() => undefined);
  return promise;
}

function untilAborted(signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) resolve();
    signal?.addEventListener("abort", () => resolve(), { once: true });
  });
}

/** A child that renames its own pid into place whole, then sleeps past every budget. */
function holdScript(pidPath: string): string {
  return `const fs = require("node:fs"); fs.writeFileSync(${JSON.stringify(`${pidPath}.tmp`)}, String(process.pid)); fs.renameSync(${JSON.stringify(`${pidPath}.tmp`)}, ${JSON.stringify(pidPath)}); setTimeout(() => {}, ${String(HOLD_MS)});`;
}

/** Every spawn of the context runs that child instead, under the options the context handed the seam. */
function blockingChildren(pidPath: string): void {
  spawnMock.mockImplementation((_command, _args, opts) =>
    actual.spawnCaptured(NODE, ["-e", holdScript(pidPath)], { ...opts, env: ENV }),
  );
}

async function storeSecret(
  value: string,
  policy: InjectionPolicyInput,
  options?: { acknowledge_interpreters: boolean },
): Promise<void> {
  await engine.createSecret({
    name: "k",
    type: "api_key",
    value: new Uint8Array(Buffer.from(value)),
  });
  secretId = await engine.resolveSecretId(HANDLE);
  await engine.setInjectionPolicy(HANDLE, policy, options);
}

async function sshTarget(command: "ssh" | "sftp"): Promise<void> {
  await storeSecret(readSshFixture("ed25519_openssh"), {
    command_allowlist: [command],
    host_allowlist: ["127.0.0.1"],
  });
  await engine.setConnectionConfig(HANDLE, {
    ssh: { known_hosts: ["127.0.0.1 ssh-ed25519 AAAA"] },
  });
}

async function gitUse(): Promise<UseSecretAction> {
  await storeSecret(`x-access-token:${randomBytes(18).toString("base64url")}`, {
    command_allowlist: ["git"],
    url_allowlist: ["https://127.0.0.1:1/*"],
  });
  return {
    type: "git",
    operation: "clone",
    repository: "https://127.0.0.1:1/harpoc/u3.git",
    working_directory: join(cloneDir, "clone"),
  };
}

/** The targets are loopback port 1 or `localhost:5999`, and every spawn runs the blocking child: nothing leaves the host. */
const CONTEXTS: {
  context: string;
  tool: string | null;
  arrange: () => Promise<UseSecretAction>;
}[] = [
  {
    context: "process",
    tool: NODE,
    arrange: async () => {
      await storeSecret(
        randomBytes(18).toString("base64url"),
        { command_allowlist: [NODE] },
        { acknowledge_interpreters: true },
      );
      return { type: "process", command: NODE, args: ["-e", ""], env_var: "TOKEN" };
    },
  },
  {
    context: "ssh",
    tool: SSH,
    arrange: async () => {
      await sshTarget("ssh");
      return { type: "ssh", host: "127.0.0.1", port: 1, user: "deploy", command: "true" };
    },
  },
  {
    context: "sftp",
    tool: SFTP,
    arrange: async () => {
      await sshTarget("sftp");
      return {
        type: "sftp",
        host: "127.0.0.1",
        port: 1,
        user: "deploy",
        operation: "list",
        remote_path: "/srv",
      };
    },
  },
  { context: "git", tool: GIT, arrange: gitUse },
  {
    context: "docker_registry",
    tool: DOCKER,
    arrange: async () => {
      await storeSecret(`harpoc-user:${randomBytes(18).toString("base64url")}`, {
        command_allowlist: ["docker"],
        host_allowlist: ["localhost:5999"],
      });
      return {
        type: "docker_registry",
        operation: "pull",
        image: "localhost:5999/harpoc/u3:1",
        timeout_ms: 300_000,
      };
    },
  },
];

function useRows(): { success: boolean; detail: Record<string, unknown> | null }[] {
  return engine
    .queryAudit({ eventType: AuditEventType.SECRET_USE, secretId })
    .reverse()
    .map((row) => ({ success: row.success, detail: row.detail }));
}

async function childOf(pidPath: string, use: Promise<unknown>): Promise<number> {
  await untilWritten(pidPath, use, MARKER_BOUND_MS);
  const pid = Number(readFileSync(pidPath, "utf8"));
  survivor = Number.isInteger(pid) && pid > 0 ? pid : undefined;
  expect(survivor).toBeDefined();
  return survivor as number;
}

async function untilGone(pid: number): Promise<void> {
  await vi.waitFor(() => expect(isAlive(pid)).toBe(false), {
    timeout: GONE_TIMEOUT_MS,
    interval: 50,
  });
  survivor = undefined;
}

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-use-lock-children-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  cloneDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-ulc-clone-")));
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  spawnMock.mockReset();
}, HOOK_TIMEOUT_MS);

afterEach(async () => {
  if (survivor !== undefined) {
    try {
      process.kill(survivor, "SIGKILL");
    } catch {
      // Already gone.
    }
    survivor = undefined;
  }
  await pending?.catch(() => undefined);
  pending = undefined;
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  rmSync(cloneDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}, HOOK_TIMEOUT_MS);

describe("a wipe under a use with a child", () => {
  describe.each(CONTEXTS)("the $context context", ({ context, tool, arrange }) => {
    it.skipIf(tool === null)(
      `a wipe ends the child of a ${context} use`,
      async () => {
        const pidFile = join(tempDir, "child.pid");
        blockingChildren(pidFile);
        const action = await arrange();
        pending = quiet(engine.useSecret(HANDLE, action));
        const pid = await childOf(pidFile, pending);

        at().sealExpired();
        at().sealExpired();

        await untilGone(pid);
        await expectVaultError(() => pending as Promise<unknown>, ErrorCode.VAULT_LOCKED);
        await engine.unlock("password");
        expect(useRows()).toStrictEqual([
          {
            success: false,
            detail: { handle: HANDLE, context, error: ErrorCode.VAULT_LOCKED },
          },
        ]);
      },
      ROW_TIMEOUT_MS,
    );
  });

  it.skipIf(GIT === null)(
    "a git use starts no later step after a wipe",
    async () => {
      const entered = deferred<undefined>();
      const gate = deferred<undefined>();
      let calls = 0;
      spawnMock.mockImplementation(async (_command, _args, opts) => {
        calls += 1;
        if (calls === 1) {
          entered.resolve(undefined);
          await Promise.race([untilAborted(opts.signal), gate.promise]);
        }
        return opts.signal?.aborted ? KILLED : EXITED;
      });
      const action = await gitUse();
      pending = quiet(engine.useSecret(HANDLE, action));
      await Promise.race([entered.promise, pending]);

      at().sealExpired();
      gate.resolve(undefined);

      await expectVaultError(() => pending as Promise<unknown>, ErrorCode.VAULT_LOCKED);
      expect(calls).toBe(1);
    },
    ROW_TIMEOUT_MS,
  );

  describe.skipIf(SSH_ON_PATH === null)("a bootstrap", () => {
    it(
      "a wipe ends a bootstrap's child and writes no row",
      async () => {
        const pidFile = join(tempDir, "child.pid");
        blockingChildren(pidFile);
        await storeSecret(randomBytes(18).toString("base64url"), {
          command_allowlist: ["ssh"],
          ssh_bootstrap: BLOCK,
        });
        at().sshBootstrap = {
          ...at().sshBootstrap,
          refuseVaultHost: () => undefined,
          refuseOldClient: () => Promise.resolve(),
        };
        pending = quiet(engine.useSecret(HANDLE, BOOT));
        const pid = await childOf(pidFile, pending);
        const markAt = at().store.readBootstrapMark(secretId)?.at;
        expect(markAt).toBeDefined();

        await engine.lock();

        await untilGone(pid);
        await expectVaultError(() => pending as Promise<unknown>, ErrorCode.VAULT_LOCKED);
        await engine.unlock("password");
        expect(useRows()).toStrictEqual([{ success: true, detail: { ...B0, began: true } }]);
        expect(
          engine.queryAudit({ eventType: AuditEventType.SECRET_REVOKE, secretId }),
        ).toStrictEqual([]);
        expect(at().store.getSecret(secretId)?.status).toBe(SecretStatus.ACTIVE);
        expect(at().store.readBootstrapMark(secretId)?.at).toBe(markAt);
      },
      ROW_TIMEOUT_MS,
    );
  });
});
