import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { Server } from "node:net";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, InjectionPolicyInput, UseSecretAction } from "@harpoc/shared";
import {
  ErrorCode,
  PrincipalType,
  SecretStatus,
  VaultError,
  recordOf,
  vaultText,
} from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { installRenderSeam, registerAgents, registryOf } from "./__fixtures__/engine-seams.js";
import { resolveNativeSshClient } from "./injection/__fixtures__/native-ssh-client.js";
import { approval, ENTRY, keyPolicy } from "./injection/__fixtures__/render-entries.js";
import { BLOCK, BOOT } from "./injection/__fixtures__/ssh-public-keys.js";
import { controlledPathDirs } from "./injection/allowlist.js";
import { leaveFixed } from "./injection/error-pass.js";
import { forceFsIsolationUnavailableForTests } from "./injection/fs-isolation.js";
import { forceNetworkIsolationUnavailableForTests } from "./injection/network-isolation.js";
import type { RenderControl, RenderPlan } from "./injection/sftp-render.js";
import { runRender } from "./injection/sftp-render.js";
import type { SpawnCapturedResult } from "./injection/spawn-captured.js";
import { redactCaptured } from "./injection/spawn-captured.js";
import { EphemeralSshAgent } from "./injection/ssh-agent/index.js";
import type {
  BootstrapCall,
  BootstrapExpected,
  BootstrapOutcome,
} from "./injection/ssh-injector-bootstrap.js";
import { readBootstrapOutcome, runBootstrap } from "./injection/ssh-injector-bootstrap.js";
import {
  forceJobWrapperUnavailableForTests,
  resetJobWrapperProbeForTests,
  resolveJobWrapper,
} from "./injection/win32-job-wrapper.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import type { SshBootstrapSeam } from "./vault-engine.js";
import { VaultEngine } from "./vault-engine.js";
import { system32Path } from "./win32-paths.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);
vi.mock("./injection/error-pass.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/error-pass.js")>();
  return { ...actual, leaveFixed: vi.fn(actual.leaveFixed) };
});
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, randomBytes: vi.fn(actual.randomBytes) };
});
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, mkdtempSync: vi.fn(actual.mkdtempSync) };
});

const { randomBytes: realRandomBytes } =
  await vi.importActual<typeof import("node:crypto")>("node:crypto");
const { mkdtempSync: realMkdtempSync } = await vi.importActual<typeof import("node:fs")>("node:fs");

// A render resolves `ssh` as the product does; on Windows only the native Win32-OpenSSH client
// is accepted, so its directory leads the PATH. A host without one skips both paths.
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}
const SSH = resolveNativeSshClient("ssh");
const itSsh = it.skipIf(SSH === null);

const FIXED_TEXT = "the operation failed";
const SSH_FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "injection",
  "__fixtures__",
  "ssh",
);
const KEY_PEM = readFileSync(join(SSH_FIXTURES, "ed25519_openssh"), "utf8");
const TRUNCATED_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from("openssh-key-v1\0").toString("base64")}\n-----END OPENSSH PRIVATE KEY-----\n`;

// Fixed on purpose: a drawn password is part of no message; each is a word of the texts it is used with.
const WORD_THE = "the";
const WORD_SECRET = "secret";
const WORD_LOCKED = "locked";
const WORD_FAILED = "failed";
const WORD_AND = "and";
const WORD_MARKS = "marks";

// The helper's word and the script's frame of a reading: upper-case letters, so no form of a lower-case password is in them.
const WORD_MARK = "QWERTYUIOPASDFGHJKLZXCVB";
const FRAME_MARK = "MNBVCXZLKJHGFDSAPOIUYTRE";
const STATUS_PREFIX = "harpoc-bootstrap-v1";
const MARKS_DRAWN = "marksmarksmarksmarksmark";

const NO_NAMESPACE = "no network namespace on this host";
const NO_MECHANISM = "no mechanism on this host";
const NO_WRAPPER = "no job wrapper on this host";

let tempDir: string;
let engine: VaultEngine;

function bytes(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "utf8"));
}

function draw(): string {
  return realRandomBytes(18).toString("hex");
}

function store(): SqliteStore {
  return (engine as unknown as { store: SqliteStore }).store;
}

function handedToLeaveFixed(): unknown {
  return vi.mocked(leaveFixed).mock.calls.at(-1)?.[0];
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

/** From now on, the `nth` audit insert throws; every other one is written. */
function failAuditInsert(nth: number): void {
  const live = store();
  const insert = live.insertAuditEvent.bind(live);
  let calls = 0;
  vi.spyOn(live, "insertAuditEvent").mockImplementation(
    (...args: Parameters<SqliteStore["insertAuditEvent"]>) => {
      calls += 1;
      if (calls === nth) throw new Error("audit unavailable");
      return insert(...args);
    },
  );
}

/** The live manager's decrypt answers as before, `then` running once it has. */
function afterDecrypt(then: () => unknown): void {
  const manager = (engine as unknown as { secretManager: SecretManager }).secretManager;
  const decrypt = manager.getSecretValue.bind(manager);
  vi.spyOn(manager, "getSecretValue").mockImplementation(
    async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      const value = await decrypt(...args);
      await then();
      return value;
    },
  );
}

/** `mkdtempSync` fails for a temporary directory of this prefix; every other is made. */
function failTempDir(prefix: string): void {
  vi.mocked(mkdtempSync).mockImplementation((path, options) => {
    if (basename(String(path)) === prefix) {
      throw Object.assign(new Error(`ENOSPC: injected, '${String(path)}'`), { code: "ENOSPC" });
    }
    return realMkdtempSync(path, options);
  });
}

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-fixed-paths-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  vi.mocked(leaveFixed).mockClear();
}, 120_000);

afterEach(async () => {
  vi.restoreAllMocks();
  vi.mocked(randomBytes).mockReset();
  vi.mocked(mkdtempSync).mockReset();
  forceNetworkIsolationUnavailableForTests(null);
  forceFsIsolationUnavailableForTests(null);
  forceJobWrapperUnavailableForTests(null);
  resetJobWrapperProbeForTests();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

// ---------------------------------------------------------------------------
// The ssh bootstrap
// ---------------------------------------------------------------------------

const HANDLE = "secret://pw";
const MARK_AT = 1_700_000_000_000;
const SPAWN = { exit_code: 0, timed_out: false, network_isolation: false, fs_isolation: false };
const DONE: BootstrapOutcome = {
  kind: "done",
  key: "installed",
  sudoers: "not_asked",
  spawn: SPAWN,
};

const BOOT_TEXT = {
  locked: "Vault is locked",
  shape:
    "the stored value cannot be an ssh password: it is empty, is no UTF-8 text, holds a line break or a NUL byte, or is longer than 1023 bytes",
  inFlight: "SSH bootstrap in flight: another bootstrap of this secret is running",
  unconfirmed:
    "SSH bootstrap unconfirmed: a bootstrap of this secret has no confirmed outcome, so the secret was ended; a key and a sudoers drop-in may be installed on the host",
  revoked: "Secret revoked: secret://pw",
  expired: "Secret expired: secret://pw",
  pending: "Secret secret://pw has no value set",
  internal: "the injection context failed unexpectedly",
  auditFailed: "the audit write failed unexpectedly",
  useFailed: "the use failed unexpectedly",
  notStarted: "SSH connection failed: the ssh client could not be started",
  stepFailed: "SSH bootstrap failed: no key was installed (sudoers: refused, key: not_attempted)",
  hostKey: "SSH host key does not match the pinned key",
  passwordRefused:
    "SSH bootstrap refused: the server refused the stored password; repeating the bootstrap can lock the vault host out of the server",
  notOffered: "SSH bootstrap refused: the server does not offer password login",
  connect: "SSH connection failed",
  names: "host and user must be names of letters, digits, '.', '_' and '-'",
  marks: "ssh bootstrap could not draw its marks",
  tempFile: "a temporary file of the ssh bootstrap could not be prepared",
};

let secretId: string;

function bootPolicy(extra: InjectionPolicyInput = {}): InjectionPolicyInput {
  return { command_allowlist: ["ssh"], ssh_bootstrap: BLOCK, ...extra };
}

async function storePassword(
  password: string,
  policy: InjectionPolicyInput = bootPolicy(),
): Promise<void> {
  await engine.createSecret({ name: "pw", type: "api_key", value: bytes(password) });
  secretId = await engine.resolveSecretId(HANDLE);
  await engine.setInjectionPolicy(HANDLE, policy);
}

/** Replaces the engine's bootstrap seam: the two refusals pass, `run` answers `DONE` unless overridden. */
function installSeam(overrides: Partial<SshBootstrapSeam> = {}): void {
  (engine as unknown as { sshBootstrap: SshBootstrapSeam }).sshBootstrap = {
    refuseVaultHost: () => undefined,
    refuseOldClient: () => Promise.resolve(),
    run: () => Promise.resolve(DONE),
    ...overrides,
  };
}

function boot(): Promise<unknown> {
  return engine.useSecret(HANDLE, BOOT);
}

function ran(overrides: Partial<SpawnCapturedResult>): SpawnCapturedResult {
  return {
    exit_code: 0,
    stdout: "",
    stderr: "",
    timed_out: false,
    truncated: false,
    signal: null,
    spawn_failed: false,
    redacted: false,
    ...overrides,
  };
}

/** The seam reads `seen` with the product's reader, the call's redaction and marks of the test's own. */
function reading(
  seen: (call: BootstrapCall) => Partial<SpawnCapturedResult>,
): () => Promise<unknown> {
  return () => {
    installSeam({
      run: (call) => {
        const password = call.password.toString("utf8");
        const expected: BootstrapExpected = {
          word: WORD_MARK,
          frame: FRAME_MARK,
          user: call.user,
          host: call.host,
          redact: (text) => redactCaptured(text, [password]),
        };
        return Promise.resolve({
          ...readBootstrapOutcome(ran(seen(call)), expected),
          spawn: SPAWN,
        });
      },
    });
    return boot();
  };
}

/** The secret's row as the claim reads it, changed right after the decrypt. */
function changedAfterDecrypt(change: () => void): () => Promise<unknown> {
  return () => {
    installSeam();
    afterDecrypt(change);
    return boot();
  };
}

async function lostClaim(): Promise<unknown> {
  const gate = deferred<BootstrapOutcome>();
  const entered = deferred<undefined>();
  const both = deferred<undefined>();
  let arrived = 0;
  installSeam({
    refuseOldClient: () => {
      arrived += 1;
      if (arrived === 2) both.resolve(undefined);
      return both.promise;
    },
    run: () => {
      entered.resolve(undefined);
      return gate.promise;
    },
  });
  const first = quiet(boot());
  const later = quiet(boot());
  await entered.promise;
  await Promise.race([first, later]).catch(() => undefined);
  gate.resolve(DONE);
  const settled = await Promise.allSettled([first, later]);
  throw (settled.find((s) => s.status === "rejected") as PromiseRejectedResult).reason;
}

describe.skipIf(SSH === null)("every text of the bootstrap's path is the vault's own", () => {
  it.each([
    {
      site: "the keys sealed before the run",
      password: WORD_LOCKED,
      use: changedAfterDecrypt(() => engine.lock()),
      code: ErrorCode.VAULT_LOCKED,
      text: BOOT_TEXT.locked,
    },
    {
      site: "the value's shape",
      password: `${WORD_THE}\n`,
      use: () => {
        installSeam();
        return boot();
      },
      code: ErrorCode.INVALID_SSH_CONFIG,
      text: BOOT_TEXT.shape,
    },
    {
      site: "the claim another call of this engine holds",
      password: WORD_THE,
      use: lostClaim,
      code: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
      text: BOOT_TEXT.inFlight,
    },
    {
      site: "the claim that meets a mark nobody holds",
      password: WORD_THE,
      use: changedAfterDecrypt(() => store().claimBootstrapMark(secretId, "claim-other", MARK_AT)),
      code: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      text: BOOT_TEXT.unconfirmed,
    },
    {
      site: "the claim that finds the secret's row gone",
      password: WORD_SECRET,
      use: changedAfterDecrypt(() => vi.spyOn(store(), "getSecret").mockReturnValueOnce(undefined)),
      code: ErrorCode.SECRET_REVOKED,
      text: BOOT_TEXT.revoked,
    },
    {
      site: "the claim that finds the secret expired by its date",
      password: WORD_SECRET,
      use: changedAfterDecrypt(() =>
        store().updateSecret(secretId, { expires_at: Date.now() - 1 }),
      ),
      code: ErrorCode.SECRET_EXPIRED,
      text: BOOT_TEXT.expired,
    },
    {
      site: "the claim that finds the secret expired",
      password: WORD_SECRET,
      use: changedAfterDecrypt(() =>
        store().updateSecret(secretId, { status: SecretStatus.EXPIRED }),
      ),
      code: ErrorCode.SECRET_EXPIRED,
      text: BOOT_TEXT.expired,
    },
    {
      site: "the claim that finds the secret revoked",
      password: WORD_SECRET,
      use: changedAfterDecrypt(() =>
        store().updateSecret(secretId, { status: SecretStatus.REVOKED }),
      ),
      code: ErrorCode.SECRET_REVOKED,
      text: BOOT_TEXT.revoked,
    },
    {
      site: "the claim that finds the secret pending",
      password: WORD_SECRET,
      use: changedAfterDecrypt(() =>
        store().updateSecret(secretId, { status: SecretStatus.PENDING }),
      ),
      code: ErrorCode.SECRET_VALUE_REQUIRED,
      text: BOOT_TEXT.pending,
    },
    {
      site: "the claim whose status refusal throws raw",
      password: WORD_THE,
      use: changedAfterDecrypt(() => {
        store().updateSecret(secretId, { expires_at: Date.now() - 1 });
        failAuditInsert(1);
      }),
      code: ErrorCode.INTERNAL_ERROR,
      text: BOOT_TEXT.internal,
    },
    {
      site: "the claim's end of a live child failing",
      password: WORD_THE,
      use: () => {
        vi.spyOn(registryOf(engine), "terminate").mockRejectedValue(new Error("boom"));
        return changedAfterDecrypt(() =>
          store().claimBootstrapMark(secretId, "claim-other", MARK_AT),
        )();
      },
      code: ErrorCode.INTERNAL_ERROR,
      text: BOOT_TEXT.useFailed,
    },
    {
      site: "a lock under a run that throws",
      password: WORD_LOCKED,
      use: () => {
        installSeam({
          run: async () => {
            await engine.lock();
            throw new Error("the seam broke");
          },
        });
        return boot();
      },
      code: ErrorCode.VAULT_LOCKED,
      text: BOOT_TEXT.locked,
    },
    {
      site: "a lock under a run that answers",
      password: WORD_LOCKED,
      use: () => {
        installSeam({
          run: async () => {
            await engine.lock();
            return DONE;
          },
        });
        return boot();
      },
      code: ErrorCode.VAULT_LOCKED,
      text: BOOT_TEXT.locked,
    },
    {
      site: "a run that throws raw",
      password: WORD_THE,
      use: () => {
        installSeam({ run: () => Promise.reject(new Error("the seam broke")) });
        return boot();
      },
      code: ErrorCode.INTERNAL_ERROR,
      text: BOOT_TEXT.internal,
    },
    {
      site: "a run that throws raw, its row unwritten",
      password: WORD_THE,
      use: () => {
        installSeam({
          run: () => {
            failAuditInsert(1);
            return Promise.reject(new Error("the seam broke"));
          },
        });
        return boot();
      },
      code: ErrorCode.INTERNAL_ERROR,
      text: BOOT_TEXT.auditFailed,
    },
    {
      site: "an outcome nobody can confirm",
      password: WORD_THE,
      use: () => {
        installSeam({ run: () => Promise.resolve({ kind: "unconfirmed", spawn: SPAWN }) });
        return boot();
      },
      code: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      text: BOOT_TEXT.unconfirmed,
    },
    {
      site: "the reader: a client that did not start",
      password: WORD_THE,
      use: reading(() => ({ spawn_failed: true, exit_code: null })),
      code: ErrorCode.SSH_CONNECT_FAILED,
      text: BOOT_TEXT.notStarted,
    },
    {
      site: "the reader: a failed step",
      password: WORD_FAILED,
      use: reading(() => ({
        exit_code: 1,
        stdout: `Welcome\n${STATUS_PREFIX} ${FRAME_MARK} refused not_attempted\n`,
      })),
      code: ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
      text: BOOT_TEXT.stepFailed,
    },
    {
      site: "the reader: a host key that is not the pin",
      password: WORD_THE,
      use: reading(() => ({ exit_code: 255, stderr: "Host key verification failed.\r\n" })),
      code: ErrorCode.SSH_HOST_KEY_MISMATCH,
      text: BOOT_TEXT.hostKey,
    },
    {
      site: "the reader: the password refused before the helper spoke",
      password: WORD_THE,
      use: reading((call) => ({
        exit_code: 255,
        stderr: `${call.user}@${call.host}: Permission denied (publickey,password).\r\n`,
      })),
      code: ErrorCode.SSH_PASSWORD_REFUSED,
      text: BOOT_TEXT.passwordRefused,
    },
    {
      site: "the reader: no password method",
      password: WORD_THE,
      use: reading((call) => ({
        exit_code: 255,
        stderr: `${call.user}@${call.host}: Permission denied (publickey).\r\n`,
      })),
      code: ErrorCode.SSH_PASSWORD_NOT_OFFERED,
      text: BOOT_TEXT.notOffered,
    },
    {
      site: "the reader: no connection",
      password: WORD_FAILED,
      use: reading(() => ({ exit_code: 255 })),
      code: ErrorCode.SSH_CONNECT_FAILED,
      text: BOOT_TEXT.connect,
    },
    {
      site: "the reader: the password refused after the helper spoke once",
      password: WORD_THE,
      use: reading((call) => ({
        exit_code: 255,
        stderr: `\n${WORD_MARK}\n${call.user}@${call.host}: Permission denied (publickey,password).\r\n`,
      })),
      code: ErrorCode.SSH_PASSWORD_REFUSED,
      text: BOOT_TEXT.passwordRefused,
    },
    {
      site: "the run: a host that is no name",
      password: WORD_AND,
      use: () => {
        installSeam({ run: (call, signal) => runBootstrap({ ...call, host: "-h1" }, signal) });
        return boot();
      },
      code: ErrorCode.INVALID_SSH_CONFIG,
      text: BOOT_TEXT.names,
    },
    {
      site: "the run: marks it cannot draw",
      password: WORD_MARKS,
      use: () => {
        installSeam({
          run: async (call, signal) => {
            vi.mocked(randomBytes).mockImplementation(((size: number) =>
              size === 18
                ? Buffer.from(MARKS_DRAWN, "base64url")
                : realRandomBytes(size)) as typeof randomBytes);
            try {
              return await runBootstrap(call, signal);
            } finally {
              vi.mocked(randomBytes).mockReset();
            }
          },
        });
        return boot();
      },
      code: ErrorCode.INTERNAL_ERROR,
      text: BOOT_TEXT.marks,
    },
    {
      site: "the run: a temporary file it cannot prepare",
      password: WORD_THE,
      use: () => {
        failTempDir("harpoc-ssh-");
        installSeam({ run: runBootstrap });
        return boot();
      },
      code: ErrorCode.FILE_IO_ERROR,
      text: BOOT_TEXT.tempFile,
    },
    {
      site: "the spawn seam: no network isolation",
      password: WORD_THE,
      policy: bootPolicy({ network_isolation: true }),
      use: () => {
        forceNetworkIsolationUnavailableForTests(vaultText`no network namespace on this host`);
        installSeam({ run: runBootstrap });
        return boot();
      },
      code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
      text: VaultError.networkIsolationUnavailable(NO_NAMESPACE).message,
    },
    {
      site: "the spawn seam: no filesystem isolation",
      password: WORD_THE,
      policy: bootPolicy({ fs_isolation: true }),
      use: () => {
        forceFsIsolationUnavailableForTests(vaultText`no mechanism on this host`);
        installSeam({ run: runBootstrap });
        return boot();
      },
      code: ErrorCode.FS_ISOLATION_UNAVAILABLE,
      text: VaultError.fsIsolationUnavailable(NO_MECHANISM).message,
    },
  ])(
    "$site reads letter for letter, from its record",
    async ({ password, policy, use, code, text }) => {
      await storePassword(password, policy);

      const err = await expectVaultError(use, code);

      expect(err.message).toBe(text);
      expect(recordOf(handedToLeaveFixed())).toBeDefined();
    },
  );

  it.runIf(process.platform === "win32")(
    "the spawn seam: no job wrapper for a strict tree exit reads letter for letter, from its record",
    async () => {
      await storePassword(WORD_THE, bootPolicy({ strict_tree_exit: true }));
      forceJobWrapperUnavailableForTests(vaultText`no job wrapper on this host`);
      installSeam({ run: runBootstrap });

      const err = await expectVaultError(boot, ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE);

      expect(err.message).toBe(VaultError.strictTreeExitUnavailable(NO_WRAPPER).message);
      expect(recordOf(handedToLeaveFixed())).toBeDefined();
    },
  );
});

// ---------------------------------------------------------------------------
// The sftp render
// ---------------------------------------------------------------------------

const KEY = "secret://deploy-key";
const BOT = "secret://bot-token";
const API = "secret://api-key";
const DB = "secret://db-pass";
const SLOTS = [BOT, API, DB];
const ALICE: CallerContext = { principal_type: "agent", principal_id: "alice", interface: "rest" };

const RENDER_TEXT = {
  names: "host and user must be names of letters, digits, '.', '_' and '-'",
  hostKey: "Vault corrupted: a render host key line does not parse",
  locked: "Vault is locked",
  tempFile: "a temporary file of the sftp render could not be prepared",
  malformedKey: "Ephemeral ssh-agent failed: malformed OpenSSH private key",
  agentDir: "Ephemeral ssh-agent failed: the agent's socket directory could not be created",
  bound: "Ephemeral ssh-agent failed: the agent's socket could not be bound (EMFILE)",
  auditFailed: "the audit write failed unexpectedly",
  injectionFailed: "the injection context failed unexpectedly",
  slotRefused: VaultError.renderSlotRefused().message,
  valueUnsupported: VaultError.renderValueUnsupported().message,
  failed: VaultError.renderFailed().message,
};
const KEY_ROW_UNREAD = "Vault corrupted: the key's row does not parse";

let values: Record<string, string>;

function render(): UseSecretAction {
  return { type: "sftp", operation: "render", entry: "env" } as UseSecretAction;
}

function useRender(): Promise<unknown> {
  return engine.useSecret(KEY, render(), ALICE);
}

async function makeSecret(handle: string, value: string): Promise<string> {
  await engine.createSecret({
    name: handle.slice("secret://".length),
    type: "api_key",
    value: bytes(value),
  });
  return engine.resolveSecretId(handle);
}

/** Two slots' values, each a word of the row's text. */
async function slotWords([bot, api]: readonly [string, string]): Promise<void> {
  await engine.rotateSecret(BOT, bytes(bot));
  await engine.rotateSecret(API, bytes(api));
}

/** The real run, handed a plan and a control the row changes. */
function runWith(
  plan: (given: RenderPlan) => RenderPlan,
  control: (given: RenderControl) => RenderControl = (given) => given,
): void {
  installRenderSeam(engine, undefined, {
    run: (given, controlGiven) => runRender(plan(given), control(controlGiven)),
  });
}

function withPolicy(extra: Partial<RenderPlan["policy"]>): (given: RenderPlan) => RenderPlan {
  return (given) => ({ ...given, policy: { ...given.policy, ...extra } });
}

/** The live manager's decrypt of `handle` answers as `answer` says; every other decrypt is real. */
function onDecryptOf(
  handle: string,
  answer: (
    decrypt: () => Promise<Uint8Array>,
    onResolved: ((secretId: string) => void) | undefined,
  ) => Promise<Uint8Array>,
): void {
  const manager = (engine as unknown as { secretManager: SecretManager }).secretManager;
  const decrypt = manager.getSecretValue.bind(manager);
  vi.spyOn(manager, "getSecretValue").mockImplementation(
    (target: string, onResolved?: (secretId: string) => void) =>
      target === handle
        ? answer(() => decrypt(target, onResolved), onResolved)
        : decrypt(target, onResolved),
  );
}

function sealDuringDecryptOf(handle: string): void {
  onDecryptOf(handle, async (decrypt) => {
    const value = await decrypt();
    await engine.lock();
    return value;
  });
}

function failNextBind(err: Error): void {
  vi.spyOn(Server.prototype, "listen").mockImplementationOnce(function (this: Server) {
    process.nextTick(() => this.emit("error", err));
    return this;
  });
}

describe("every text of the render's path is the vault's own", () => {
  beforeEach(async () => {
    values = { [KEY]: KEY_PEM, [BOT]: draw(), [API]: draw(), [DB]: draw() };
    const keyId = await makeSecret(KEY, KEY_PEM);
    const ids = [keyId];
    for (const handle of SLOTS) ids.push(await makeSecret(handle, values[handle] as string));
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY]));
    for (const handle of SLOTS) {
      await engine.setInjectionPolicy(handle, {
        render: { entries: [], approvals: [approval(keyId, ENTRY)] },
      });
    }
    registerAgents(engine, "alice");
    for (const id of ids) {
      engine.grantPolicy(
        {
          secretId: id,
          principalType: PrincipalType.AGENT,
          principalId: "alice",
          permissions: ["use"],
        },
        "test",
      );
    }
  }, 120_000);

  itSsh.each([
    {
      site: "the run: a user that is no name",
      words: ["names", "letters"] as const,
      arrange: () => runWith((given) => ({ ...given, entry: { ...given.entry, user: "-deploy" } })),
      code: ErrorCode.INVALID_SSH_CONFIG,
      text: RENDER_TEXT.names,
    },
    {
      site: "the run: a host key line it cannot read",
      words: ["render", "parse"] as const,
      arrange: () =>
        runWith((given) => ({
          ...given,
          entry: { ...given.entry, host_keys: ["not a host key"] },
        })),
      code: ErrorCode.VAULT_CORRUPTED,
      text: RENDER_TEXT.hostKey,
    },
    {
      site: "the run: a seal before its files",
      words: ["Vault", "locked"] as const,
      arrange: () =>
        runWith(
          (given) => given,
          (given) => ({ signal: AbortSignal.abort(), written: given.written }),
        ),
      code: ErrorCode.VAULT_LOCKED,
      text: RENDER_TEXT.locked,
    },
    {
      site: "the run: a temporary file it cannot prepare",
      words: ["temporary", "render"] as const,
      arrange: () => {
        failTempDir("harpoc-ssh-");
        runWith((given) => given);
      },
      code: ErrorCode.FILE_IO_ERROR,
      text: RENDER_TEXT.tempFile,
    },
    {
      site: "the agent: a key its loader cannot read",
      words: ["malformed", "private"] as const,
      arrange: async () => {
        await engine.rotateSecret(KEY, bytes(TRUNCATED_KEY));
        runWith((given) => given);
      },
      code: ErrorCode.SSH_AGENT_FAILED,
      text: RENDER_TEXT.malformedKey,
    },
    {
      site: "the agent: a socket it cannot bind",
      words: ["socket", "bound"] as const,
      arrange: () => {
        failNextBind(
          Object.assign(new Error("listen EMFILE: too many open files"), { code: "EMFILE" }),
        );
        runWith((given) => given);
      },
      code: ErrorCode.SSH_AGENT_FAILED,
      text: RENDER_TEXT.bound,
    },
    {
      site: "the run: a seal after the agent started",
      words: ["Vault", "locked"] as const,
      arrange: () => {
        let reads = 0;
        const signal = {
          get aborted(): boolean {
            reads += 1;
            return reads > 1;
          },
        } as unknown as AbortSignal;
        runWith(
          (given) => given,
          (given) => ({ signal, written: given.written }),
        );
      },
      code: ErrorCode.VAULT_LOCKED,
      text: RENDER_TEXT.locked,
    },
    {
      site: "the spawn seam: no filesystem isolation",
      words: ["isolation", "Filesystem"] as const,
      arrange: () => {
        forceFsIsolationUnavailableForTests(vaultText`no mechanism on this host`);
        runWith(withPolicy({ fs_isolation: true }));
      },
      code: ErrorCode.FS_ISOLATION_UNAVAILABLE,
      text: VaultError.fsIsolationUnavailable(NO_MECHANISM).message,
    },
    {
      site: "the spawn seam: no network isolation",
      words: ["isolation", "namespace"] as const,
      arrange: () => {
        forceNetworkIsolationUnavailableForTests(vaultText`no network namespace on this host`);
        runWith(withPolicy({ network_isolation: true }));
      },
      code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
      text: VaultError.networkIsolationUnavailable(NO_NAMESPACE).message,
    },
  ])("$site reads letter for letter, from its record", async ({ words, arrange, code, text }) => {
    await slotWords(words);
    await arrange();

    const err = await expectVaultError(useRender, code);

    expect(err.message).toBe(text);
    expect(recordOf(handedToLeaveFixed())).toBeDefined();
  });

  it.runIf(SSH !== null && process.platform === "win32")(
    "the spawn seam: no job wrapper for a strict tree exit reads letter for letter, from its record",
    async () => {
      await slotWords(["wrapper", "Windows"]);
      forceJobWrapperUnavailableForTests(vaultText`no job wrapper on this host`);
      runWith(withPolicy({ strict_tree_exit: true }));

      const err = await expectVaultError(useRender, ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE);

      expect(err.message).toBe(VaultError.strictTreeExitUnavailable(NO_WRAPPER).message);
      expect(recordOf(handedToLeaveFixed())).toBeDefined();
    },
  );

  // POSIX only: on win32 the agent serves a named pipe, with no socket directory and no path bound.
  it.skipIf(SSH === null || process.platform === "win32")(
    "the agent: a socket directory it cannot create reads letter for letter, from its record",
    async () => {
      await slotWords(["socket", "directory"]);
      failTempDir("harpoc-agent-");
      runWith((given) => given);

      const err = await expectVaultError(useRender, ErrorCode.SSH_AGENT_FAILED);

      expect(err.message).toBe(RENDER_TEXT.agentDir);
      expect(recordOf(handedToLeaveFixed())).toBeDefined();
    },
  );

  it.skipIf(SSH === null || process.platform === "win32")(
    "the agent: a socket path over the bound reads letter for letter, from its record",
    async () => {
      const long = realMkdtempSync(join(tmpdir(), `harpoc-fp-${"x".repeat(100)}`));
      const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
      try {
        process.env.TMPDIR = long;
        process.env.TMP = long;
        process.env.TEMP = long;
        const refusal = await expectVaultError(
          () => EphemeralSshAgent.start(KEY_PEM),
          ErrorCode.SSH_AGENT_FAILED,
        );
        await slotWords(["socket", "address"]);
        runWith((given) => given);

        const err = await expectVaultError(useRender, ErrorCode.SSH_AGENT_FAILED);

        expect(err.message).toBe(refusal.message);
        expect(recordOf(handedToLeaveFixed())).toBeDefined();
      } finally {
        if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
        else process.env.TMPDIR = saved.TMPDIR;
        if (saved.TMP === undefined) delete process.env.TMP;
        else process.env.TMP = saved.TMP;
        if (saved.TEMP === undefined) delete process.env.TEMP;
        else process.env.TEMP = saved.TEMP;
        rmSync(long, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    },
  );

  itSsh.each([
    {
      site: "a seal during the key's decrypt",
      words: ["Vault", "locked"] as const,
      arrange: () => {
        installRenderSeam(engine);
        sealDuringDecryptOf(KEY);
      },
      code: ErrorCode.VAULT_LOCKED,
      text: RENDER_TEXT.locked,
    },
    {
      site: "a seal during a slot's decrypt",
      words: ["Vault", "locked"] as const,
      arrange: () => {
        installRenderSeam(engine);
        sealDuringDecryptOf(BOT);
      },
      code: ErrorCode.VAULT_LOCKED,
      text: RENDER_TEXT.locked,
    },
    {
      site: "a seal during the run",
      words: ["Vault", "locked"] as const,
      arrange: () => {
        installRenderSeam(engine, async () => {
          await engine.lock();
          return undefined;
        });
      },
      code: ErrorCode.VAULT_LOCKED,
      text: RENDER_TEXT.locked,
    },
    {
      site: "a slot's decrypt that fails under another secret",
      words: ["slot", "template"] as const,
      arrange: () => {
        installRenderSeam(engine);
        onDecryptOf(DB, (_decrypt, onResolved) => {
          onResolved?.("another-secret");
          return Promise.reject(new Error("the decrypt broke"));
        });
      },
      code: ErrorCode.RENDER_SLOT_REFUSED,
      text: RENDER_TEXT.slotRefused,
    },
    {
      site: "a slot's decrypt that names another secret",
      words: ["slot", "template"] as const,
      arrange: () => {
        installRenderSeam(engine);
        onDecryptOf(DB, async (decrypt, onResolved) => {
          const value = await decrypt();
          onResolved?.("another-secret");
          return value;
        });
      },
      code: ErrorCode.RENDER_SLOT_REFUSED,
      text: RENDER_TEXT.slotRefused,
    },
    {
      site: "a value the template does not take",
      words: ["value", "template"] as const,
      arrange: () => {
        installRenderSeam(engine);
        onDecryptOf(DB, async (decrypt) => {
          (await decrypt()).fill(0);
          return bytes(`${draw()}!`);
        });
      },
      code: ErrorCode.RENDER_VALUE_UNSUPPORTED,
      text: RENDER_TEXT.valueUnsupported,
    },
    {
      site: "a failed write",
      words: ["render", "written"] as const,
      arrange: () => {
        installRenderSeam(engine, () => ({
          kind: "ran",
          outcome: { written: "no", reason: "connect" },
          spawn: { network_isolation: false, fs_isolation: false },
        }));
      },
      code: ErrorCode.RENDER_FAILED,
      text: RENDER_TEXT.failed,
    },
    {
      site: "the rows' commit failing",
      words: ["audit", "write"] as const,
      arrange: () => {
        installRenderSeam(engine, () => {
          failAuditInsert(1);
          return undefined;
        });
      },
      code: ErrorCode.INTERNAL_ERROR,
      text: RENDER_TEXT.auditFailed,
    },
    {
      site: "a run that throws raw",
      words: ["injection", "context"] as const,
      arrange: () => {
        installRenderSeam(engine, () => {
          throw new Error("the seam broke");
        });
      },
      code: ErrorCode.INTERNAL_ERROR,
      text: RENDER_TEXT.injectionFailed,
    },
  ])(
    "the arm's own exit: $site reads letter for letter, from its record",
    async ({ words, arrange, code, text }) => {
      await slotWords(words);
      arrange();

      const err = await expectVaultError(useRender, code);

      expect(err.message).toBe(text);
      expect(vi.mocked(leaveFixed)).toHaveBeenCalledTimes(1);
      expect(recordOf(handedToLeaveFixed())).toBeDefined();
    },
  );

  itSsh("the key's own decrypt failure leaves as it stands, unpassed", async () => {
    installRenderSeam(engine);
    onDecryptOf(KEY, () =>
      Promise.reject(new VaultError(ErrorCode.VAULT_CORRUPTED, KEY_ROW_UNREAD)),
    );

    const err = await expectVaultError(useRender, ErrorCode.VAULT_CORRUPTED);

    expect(err.message).toBe(KEY_ROW_UNREAD);
    expect(leaveFixed).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Errors nobody classified, and the spawn seam's reasons
// ---------------------------------------------------------------------------

describe("an error nobody classified leaves with its code and the fixed text", () => {
  itSsh("the bootstrap's seam throwing a VaultError", async () => {
    const password = realRandomBytes(18).toString("base64url");
    await storePassword(password);
    installSeam({
      run: () =>
        Promise.reject(new VaultError(ErrorCode.SSH_CONNECT_FAILED, "peer wrote " + password)),
    });

    const err = await expectVaultError(boot, ErrorCode.SSH_CONNECT_FAILED);

    expectAbsent(err.message, password);
    expect(err.message).toBe(FIXED_TEXT);
    expect(recordOf(handedToLeaveFixed())).toBeUndefined();
  });

  itSsh("the bootstrap's not_spawned answer built from a plain string", async () => {
    const password = realRandomBytes(18).toString("base64url");
    await storePassword(password);
    installSeam({
      run: () =>
        Promise.resolve({
          kind: "not_spawned",
          error: new VaultError(ErrorCode.FS_ISOLATION_UNAVAILABLE, `plain ${password}`),
        }),
    });

    const err = await expectVaultError(boot, ErrorCode.FS_ISOLATION_UNAVAILABLE);

    expectAbsent(err.message, password);
    expect(err.message).toBe(FIXED_TEXT);
    expect(recordOf(handedToLeaveFixed())).toBeUndefined();
  });

  describe("the render", () => {
    beforeEach(async () => {
      values = { [KEY]: draw(), [BOT]: draw(), [API]: draw(), [DB]: draw() };
      const keyId = await makeSecret(KEY, values[KEY] as string);
      const ids = [keyId];
      for (const handle of SLOTS) ids.push(await makeSecret(handle, values[handle] as string));
      await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY]));
      for (const handle of SLOTS) {
        await engine.setInjectionPolicy(handle, {
          render: { entries: [], approvals: [approval(keyId, ENTRY)] },
        });
      }
    }, 120_000);

    itSsh("its run throwing a VaultError", async () => {
      installRenderSeam(engine, () => {
        throw new VaultError(ErrorCode.SSH_AGENT_FAILED, `agent down for ${values[DB] as string}`);
      });

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render()),
        ErrorCode.SSH_AGENT_FAILED,
      );

      expectAbsent(err.message, values[DB] as string);
      expect(err.message).toBe(FIXED_TEXT);
      expect(recordOf(handedToLeaveFixed())).toBeUndefined();
    });

    itSsh("its not_spawned answer built from a plain string", async () => {
      installRenderSeam(engine, () => ({
        kind: "not_spawned",
        error: new VaultError(ErrorCode.FS_ISOLATION_UNAVAILABLE, `plain ${values[API] as string}`),
      }));

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render()),
        ErrorCode.FS_ISOLATION_UNAVAILABLE,
      );

      expectAbsent(err.message, values[API] as string);
      expect(err.message).toBe(FIXED_TEXT);
      expect(recordOf(handedToLeaveFixed())).toBeUndefined();
    });

    itSsh("the rows' commit failing with an error of its own", async () => {
      installRenderSeam(engine, () => {
        vi.spyOn(store(), "insertAuditEvent").mockImplementation(() => {
          throw new VaultError(ErrorCode.DATABASE_ERROR, `the disk said ${values[DB] as string}`);
        });
        return undefined;
      });

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render()),
        ErrorCode.DATABASE_ERROR,
      );

      expectAbsent(err.message, values[DB] as string);
      expect(err.message).toBe(FIXED_TEXT);
      expect(vi.mocked(leaveFixed)).toHaveBeenCalledTimes(1);
      expect(recordOf(handedToLeaveFixed())).toBeUndefined();
    });

    itSsh("a terminate after a slot's refusal failing with an error of its own", async () => {
      installRenderSeam(engine);
      onDecryptOf(DB, () => Promise.reject(new Error("the decrypt broke")));
      const broke = new VaultError(ErrorCode.DATABASE_ERROR, `plain ${values[KEY] as string}`);
      vi.spyOn(registryOf(engine), "terminate").mockRejectedValue(broke);

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render()),
        ErrorCode.DATABASE_ERROR,
      );

      expectAbsent(err.message, values[KEY] as string);
      expect(err.message).toBe(FIXED_TEXT);
      expect(handedToLeaveFixed()).toBe(broke);
      expect(recordOf(broke)).toBeUndefined();
    });
  });
});

// The strict refusal is the taskkill tier's alone: off win32 a strict spawn runs without a wrapper.
describe.runIf(process.platform === "win32")(
  "a spawn-seam refusal names a code or the fixed words",
  () => {
    const HELPER_TEXT = "helper-text-marker-5b1d";

    itSsh.each([
      {
        what: "a code",
        failure: () => Object.assign(new Error(`spawn ${HELPER_TEXT} ENOENT`), { code: "ENOENT" }),
        reason: "compile failed: csc did not complete: ENOENT",
      },
      {
        what: "no code",
        failure: () => new Error(`spawn ${HELPER_TEXT}`),
        reason: "compile failed: csc did not complete: unknown error",
      },
    ])("the job wrapper's seam failing with $what", async ({ failure, reason }) => {
      const dir = join(tempDir, "job");
      mkdirSync(dir);
      const csc = join(dir, "csc.exe");
      writeFileSync(csc, "");
      resetJobWrapperProbeForTests();
      await resolveJobWrapper({
        platform: "win32",
        compilerCandidates: [csc],
        cacheDirs: [join(dir, "cache")],
        probeBinary: existsSync,
        runHelper: () => Promise.reject(failure()),
        restrictDir: () => undefined,
      });
      await storePassword(WORD_THE, bootPolicy({ strict_tree_exit: true }));
      installSeam({ run: runBootstrap });

      const err = await expectVaultError(boot, ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE);

      expectAbsent(err.message, HELPER_TEXT);
      expect(err.message).toBe(VaultError.strictTreeExitUnavailable(reason).message);
      expect(recordOf(handedToLeaveFixed())).toBeDefined();
    });
  },
);
