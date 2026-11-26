import { randomBytes } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, InjectionPolicyInput, UseSecretAction } from "@harpoc/shared";
import {
  AuditEventType,
  ErrorCode,
  SecretStatus,
  SSH_HOST_KEY_TYPES,
  SSH_INSTALL_KEY_TYPES,
  VaultError,
} from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import {
  nonReadAuditCount,
  registerAgents,
  registryOf,
  retainDecryptedValues,
  seedLiveStdioEntry,
} from "./__fixtures__/engine-seams.js";
import {
  B0,
  BLOCK,
  BOOT,
  HOST_KEY,
  KEY_A,
  KEY_B,
  KEY_ECDSA_384,
  SSH_PUBLIC_KEY_VECTORS,
} from "./injection/__fixtures__/ssh-public-keys.js";
import { controlledPathDirs, resolveExecutable } from "./injection/allowlist.js";
import { parseSshPublicKey } from "./injection/ssh-common-keys.js";
import { refuseUnsupportedSshClient } from "./injection/ssh-common-version.js";
import type { BootstrapCall, BootstrapOutcome } from "./injection/ssh-injector-bootstrap.js";
import { refuseWindowsVaultHost, runBootstrap } from "./injection/ssh-injector-bootstrap.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import type { SshBootstrapSeam } from "./vault-engine.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// From the allowlist on, a bootstrap resolves `ssh` on the vault's PATH; a host without one skips.
const SSH_ON_PATH = resolveExecutable("ssh", controlledPathDirs());

const HANDLE = "secret://pw";
const MARK_AT = 1_700_000_000_000;
const SPAWN = { exit_code: 0, timed_out: false, network_isolation: false, fs_isolation: false };
const DONE: BootstrapOutcome = {
  kind: "done",
  key: "installed",
  sudoers: "not_asked",
  spawn: SPAWN,
};
const RESULT = { type: "ssh_bootstrap", key: "installed", sudoers: "not_asked" };
const POLICY: InjectionPolicyInput = { command_allowlist: ["ssh"], ssh_bootstrap: BLOCK };
const FP_384 = SSH_PUBLIC_KEY_VECTORS.find((v) => v.line === KEY_ECDSA_384)?.fingerprint;
const FLOOR_REFUSAL = VaultError.sshClientBelowFloor("8.3", "8.4");

const TEXT = {
  noBlock: "SSH bootstrap not allowed: the secret's injection policy holds no bootstrap block",
  target: "SSH bootstrap not allowed: host, user or port is not the bootstrap block's",
  key: "SSH bootstrap not allowed: the public key is not one the bootstrap block lists",
  sudoers: "SSH bootstrap not allowed: the bootstrap block does not allow the sudoers rule",
  windows: "Unsupported ssh client: the ssh bootstrap is not served on a Windows vault host",
  allowlist: "Command not in secret allowlist: ssh",
  shape:
    "the stored value cannot be an ssh password: it is empty, is no UTF-8 text, holds a line break or a NUL byte, or is longer than 1023 bytes",
  unconfirmed:
    "SSH bootstrap unconfirmed: a bootstrap of this secret has no confirmed outcome, so the secret was ended; a key and a sudoers drop-in may be installed on the host",
  inFlight: "SSH bootstrap in flight: another bootstrap of this secret is running",
  stepFailed: "SSH bootstrap failed: no key was installed (sudoers: refused, key: not_attempted)",
  passwordRefused:
    "SSH bootstrap refused: the server refused the stored password; repeating the bootstrap can lock the vault host out of the server",
  revoked: "Secret revoked: secret://pw",
  internal: "the injection context failed unexpectedly",
  auditFailed: "the audit write failed unexpectedly",
};

// Fixed on purpose: a drawn password is part of no message, and these are words and a letter of the messages above.
const WORD_SECRET = "secret";
const WORD_KEY = "key";
const WORD_PASSWORD = "password";
const LETTER = "e";

let tempDir: string;
let dbPath: string;
let engine: VaultEngine;
let second: VaultEngine | undefined;
let password: string;
let secretId: string;

interface EngineInternals {
  secretManager: SecretManager;
  store: SqliteStore;
  bootstrapHolds: Map<string, string>;
  sshBootstrap: SshBootstrapSeam;
  sshInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
}

function internals(of: VaultEngine = engine): EngineInternals {
  return of as unknown as EngineInternals;
}

function store(of: VaultEngine = engine): SqliteStore {
  return internals(of).store;
}

function unparsed(value: unknown): UseSecretAction {
  return value as UseSecretAction;
}

function boot(fields: Record<string, unknown> = {}): UseSecretAction {
  return unparsed({ ...BOOT, ...fields });
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve: (value: T) => void = () => undefined;
  let reject: (reason: unknown) => void = () => undefined;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function quiet<T>(promise: Promise<T>): Promise<T> {
  promise.catch(() => undefined);
  return promise;
}

type Run = (call: BootstrapCall) => BootstrapOutcome | Promise<BootstrapOutcome>;

/** Replaces the engine's bootstrap seam: the two refusals pass, `run` records each call and answers `script`. */
function installSeam(
  at: VaultEngine,
  script: Run = () => DONE,
  overrides: Partial<SshBootstrapSeam> = {},
): BootstrapCall[] {
  const calls: BootstrapCall[] = [];
  internals(at).sshBootstrap = {
    refuseVaultHost: () => undefined,
    refuseOldClient: () => Promise.resolve(),
    run: async (call) => {
      calls.push(call);
      return await script(call);
    },
    ...overrides,
  };
  return calls;
}

async function storeSecret(
  value: Uint8Array = new Uint8Array(Buffer.from(password)),
  policy: InjectionPolicyInput = POLICY,
): Promise<void> {
  await engine.createSecret({ name: "pw", type: "api_key", value });
  secretId = await engine.resolveSecretId(HANDLE);
  await engine.setInjectionPolicy(HANDLE, policy);
}

function rowsOf(eventType: AuditEventType, at: VaultEngine = engine, id: string = secretId) {
  return at.queryAudit({ eventType, secretId: id }).reverse();
}

function useRows(at: VaultEngine = engine, id: string = secretId) {
  return rowsOf(AuditEventType.SECRET_USE, at, id).map((row) => ({
    detail: row.detail,
    success: row.success,
  }));
}

function useDetails(at: VaultEngine = engine, id: string = secretId) {
  return useRows(at, id).map((row) => row.detail);
}

function revokeDetails(at: VaultEngine = engine) {
  return rowsOf(AuditEventType.SECRET_REVOKE, at).map((row) => row.detail);
}

function statusOf(at: VaultEngine = engine): string | undefined {
  return store(at).getSecret(secretId)?.status;
}

function spyDecrypt(at: VaultEngine = engine) {
  return vi.spyOn(internals(at).secretManager, "getSecretValue");
}

function allZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
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

/** Two bootstraps of the secret sent in one tick: both pass the judgement before either claims the mark. */
async function twoInOneTick(): Promise<{
  calls: BootstrapCall[];
  settled: PromiseSettledResult<unknown>[];
}> {
  const gate = deferred<BootstrapOutcome>();
  const entered = deferred<undefined>();
  const both = deferred<undefined>();
  let arrived = 0;
  const calls = installSeam(
    engine,
    () => {
      entered.resolve(undefined);
      return gate.promise;
    },
    {
      refuseOldClient: () => {
        arrived += 1;
        if (arrived === 2) both.resolve(undefined);
        return both.promise;
      },
    },
  );
  const first = quiet(engine.useSecret(HANDLE, BOOT));
  const later = quiet(engine.useSecret(HANDLE, BOOT));
  await entered.promise;
  await Promise.race([first, later]).catch(() => undefined);
  gate.resolve(DONE);
  return { calls, settled: await Promise.allSettled([first, later]) };
}

/** The use after an outcome nobody recorded: a bootstrap meets the mark and ends the secret. */
async function expectEndedAtNextUse(at: VaultEngine, markAt: number): Promise<void> {
  const calls = installSeam(at);
  const err = await expectVaultError(
    () => at.useSecret(HANDLE, BOOT),
    ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
  );
  expect(err.message).toBe(TEXT.unconfirmed);
  expect(calls).toHaveLength(0);
  expect(useRows(at).at(-1)).toStrictEqual({
    detail: {
      ...B0,
      error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      secret_ended: true,
      mark_at: markAt,
    },
    success: false,
  });
  expect(revokeDetails(at)).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
  expect(statusOf(at)).toBe(SecretStatus.REVOKED);
  expect(store(at).readBootstrapMark(secretId)).toBeUndefined();
}

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-ssh-bootstrap-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  engine = new VaultEngine({ dbPath, sessionPath: join(tempDir, "session.json") });
  password = randomBytes(18).toString("base64url");
  await engine.initVault("password");
});

afterEach(async () => {
  vi.restoreAllMocks();
  try {
    await second?.destroy();
  } finally {
    second = undefined;
    await engine.destroy();
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

describe("the engine's bootstrap seam", () => {
  it("holds the injector's three functions", () => {
    expect(internals().sshBootstrap).toStrictEqual({
      refuseVaultHost: refuseWindowsVaultHost,
      refuseOldClient: refuseUnsupportedSshClient,
      run: runBootstrap,
    });
  });

  it.runIf(process.platform === "win32")(
    "on a Windows vault host its own refusal answers before the allowlist and the decrypt",
    async () => {
      await storeSecret(undefined, { command_allowlist: ["git"], ssh_bootstrap: BLOCK });
      const getSecretValue = spyDecrypt();

      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, BOOT),
        ErrorCode.SSH_CLIENT_UNSUPPORTED,
      );
      expect(err.message).toBe(TEXT.windows);
      expect(getSecretValue).not.toHaveBeenCalled();
      expect(useRows()).toStrictEqual([
        { detail: { ...B0, error: ErrorCode.SSH_CLIENT_UNSUPPORTED }, success: false },
      ]);
    },
  );
});

describe("useSecret — the bootstrap's refusals before the decrypt (B3)", () => {
  it("no block", async () => {
    await storeSecret(undefined, { command_allowlist: ["ssh"] });
    const calls = installSeam(engine);
    const getSecretValue = spyDecrypt();

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
    );
    expectAbsent(err.message, password);
    expect(err.message).toBe(TEXT.noBlock);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expect(useRows()).toStrictEqual([
      {
        detail: { ...B0, error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED, reason: "no_block" },
        success: false,
      },
    ]);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
  });

  it.each([
    { what: "another host", sent: { host: "h2.example" }, row: { host: "h2.example" } },
    { what: "another user", sent: { user: "root" }, row: { user: "root" } },
    { what: "another port", sent: { port: 2222 }, row: { port: 2222 } },
  ])("$what", async ({ sent, row }) => {
    await storeSecret();
    const calls = installSeam(engine);
    const getSecretValue = spyDecrypt();

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, boot(sent)),
      ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
    );
    expect(err.message).toBe(TEXT.target);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expect(useRows()).toStrictEqual([
      {
        detail: { ...B0, ...row, error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED, reason: "target" },
        success: false,
      },
    ]);
  });

  it.each([
    {
      what: "an unlisted key, by its own fingerprint",
      key: KEY_ECDSA_384,
      fingerprint: FP_384,
    },
    { what: "a listed key with its comment (no key line)", key: `${KEY_A} ops@laptop` },
    { what: "text that is no key", key: "not a key" },
  ])("a key that is not one the block lists — $what", async ({ key, fingerprint }) => {
    await storeSecret();
    const calls = installSeam(engine);
    const getSecretValue = spyDecrypt();

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, boot({ public_key: key })),
      ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
    );
    expect(err.message).toBe(TEXT.key);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    const withoutKey = Object.fromEntries(
      Object.entries(B0).filter(([field]) => field !== "key_fingerprint"),
    );
    expect(useRows()).toStrictEqual([
      {
        detail: {
          ...withoutKey,
          ...(fingerprint === undefined ? {} : { key_fingerprint: fingerprint }),
          error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
          reason: "key",
        },
        success: false,
      },
    ]);
  });

  it.skipIf(SSH_ON_PATH === null).each([{ field: "host" }, { field: "public_key" }])(
    "a field the door read as text is judged as that text, never as the type a later read answers — $field",
    async ({ field }) => {
      await storeSecret();
      const calls = installSeam(engine);
      const manager = internals().secretManager;
      const resolve = manager.resolveHandle.bind(manager);
      let pastDoor = false;
      vi.spyOn(manager, "resolveHandle").mockImplementation((handle: string) => {
        pastDoor = true;
        return resolve(handle);
      });
      let reads = 0;
      const action: Record<string, unknown> = { ...BOOT };
      const asSent = action[field];
      Object.defineProperty(action, field, {
        enumerable: true,
        get: () => {
          reads += 1;
          return pastDoor ? 42 : asSent;
        },
      });

      await expect(engine.useSecret(HANDLE, unparsed(action))).resolves.toStrictEqual(RESULT);

      expect(reads).toBe(1);
      expect(calls).toHaveLength(1);
    },
  );

  it("the sudoers flag without the opt-in", async () => {
    await storeSecret(undefined, {
      command_allowlist: ["ssh"],
      ssh_bootstrap: { ...BLOCK, sudoers: false },
    });
    const calls = installSeam(engine);
    const getSecretValue = spyDecrypt();

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, boot({ sudoers: true })),
      ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
    );
    expect(err.message).toBe(TEXT.sudoers);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expect(useRows()).toStrictEqual([
      {
        detail: {
          ...B0,
          sudoers: true,
          error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
          reason: "sudoers",
        },
        success: false,
      },
    ]);
  });

  it("a vault host on Windows", async () => {
    await storeSecret();
    const calls = installSeam(engine, () => DONE, {
      refuseVaultHost: () => {
        throw VaultError.sshBootstrapOnWindows();
      },
    });
    const getSecretValue = spyDecrypt();

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(TEXT.windows);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, error: ErrorCode.SSH_CLIENT_UNSUPPORTED }, success: false },
    ]);
  });

  it.skipIf(SSH_ON_PATH === null)("ssh not on command_allowlist", async () => {
    await storeSecret(undefined, { command_allowlist: ["git"], ssh_bootstrap: BLOCK });
    const oldClient = vi.fn(() => Promise.resolve());
    const calls = installSeam(engine, () => DONE, { refuseOldClient: oldClient });
    const getSecretValue = spyDecrypt();

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
    expect(err.message).toBe(TEXT.allowlist);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(oldClient).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, error: ErrorCode.COMMAND_NOT_ALLOWED }, success: false },
    ]);
  });

  it.skipIf(SSH_ON_PATH === null)("a client below 8.4", async () => {
    await storeSecret();
    const calls = installSeam(engine, () => DONE, {
      refuseOldClient: () => Promise.reject(FLOOR_REFUSAL),
    });
    const getSecretValue = spyDecrypt();

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(FLOOR_REFUSAL.message);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, error: ErrorCode.SSH_CLIENT_UNSUPPORTED }, success: false },
    ]);
  });
});

describe("useSecret — the refusals keep B3's order", () => {
  it.skipIf(SSH_ON_PATH === null)(
    "a call that fails checks 2 to 8 at once reports the first, and each next one in turn",
    async () => {
      const block = { ...BLOCK, sudoers: false };
      await storeSecret(undefined, { command_allowlist: ["git"], ssh_bootstrap: block });
      store().claimBootstrapMark(secretId, "claim-held", MARK_AT);
      internals().bootstrapHolds.set(secretId, "claim-held");
      let windows = true;
      let oldClient = true;
      const calls = installSeam(engine, () => DONE, {
        refuseVaultHost: () => {
          if (windows) throw VaultError.sshBootstrapOnWindows();
        },
        refuseOldClient: () => (oldClient ? Promise.reject(FLOOR_REFUSAL) : Promise.resolve()),
      });
      const getSecretValue = spyDecrypt();
      const sent: Record<string, unknown> = {
        host: "h2.example",
        public_key: KEY_ECDSA_384,
        sudoers: true,
      };

      const steps: Array<{ code: ErrorCode; message: string; then: () => Promise<void> | void }> = [
        {
          code: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
          message: TEXT.target,
          then: () => void delete sent.host,
        },
        {
          code: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
          message: TEXT.key,
          then: () => void delete sent.public_key,
        },
        {
          code: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
          message: TEXT.sudoers,
          then: () => void delete sent.sudoers,
        },
        {
          code: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
          message: TEXT.inFlight,
          then: () => {
            internals().bootstrapHolds.delete(secretId);
            store().clearBootstrapMark(secretId);
          },
        },
        {
          code: ErrorCode.SSH_CLIENT_UNSUPPORTED,
          message: TEXT.windows,
          then: () => {
            windows = false;
          },
        },
        {
          code: ErrorCode.COMMAND_NOT_ALLOWED,
          message: TEXT.allowlist,
          then: () =>
            engine.setInjectionPolicy(HANDLE, { command_allowlist: ["ssh"], ssh_bootstrap: block }),
        },
        {
          code: ErrorCode.SSH_CLIENT_UNSUPPORTED,
          message: FLOOR_REFUSAL.message,
          then: () => undefined,
        },
      ];
      for (const step of steps) {
        const err = await expectVaultError(() => engine.useSecret(HANDLE, boot(sent)), step.code);
        expect(err.message).toBe(step.message);
        await step.then();
      }
      oldClient = false;

      expect(getSecretValue).not.toHaveBeenCalled();
      expect(calls).toHaveLength(0);
      expect(useDetails()).toStrictEqual([
        {
          ...B0,
          host: "h2.example",
          key_fingerprint: FP_384,
          sudoers: true,
          error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
          reason: "target",
        },
        {
          ...B0,
          key_fingerprint: FP_384,
          sudoers: true,
          error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
          reason: "key",
        },
        { ...B0, sudoers: true, error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED, reason: "sudoers" },
        { ...B0, error: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT },
        { ...B0, error: ErrorCode.SSH_CLIENT_UNSUPPORTED },
        { ...B0, error: ErrorCode.COMMAND_NOT_ALLOWED },
        { ...B0, error: ErrorCode.SSH_CLIENT_UNSUPPORTED },
      ]);
    },
  );

  it("a mark planted beside a wrong host leaves the mark and the secret alone", async () => {
    await storeSecret();
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);
    const calls = installSeam(engine);

    await expectVaultError(
      () => engine.useSecret(HANDLE, boot({ host: "h2.example" })),
      ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
    );

    expect(useDetails()).toStrictEqual([
      {
        ...B0,
        host: "h2.example",
        error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
        reason: "target",
      },
    ]);
    expect(store().readBootstrapMark(secretId)).toEqual({ claim: "claim-other", at: MARK_AT });
    expect(statusOf()).toBe(SecretStatus.ACTIVE);
    expect(revokeDetails()).toStrictEqual([]);
    expect(calls).toHaveLength(0);
  });

  it("the Windows refusal precedes the allowlist's", async () => {
    await storeSecret(undefined, { command_allowlist: ["git"], ssh_bootstrap: BLOCK });
    installSeam(engine, () => DONE, {
      refuseVaultHost: () => {
        throw VaultError.sshBootstrapOnWindows();
      },
    });

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(TEXT.windows);
    expect(useDetails()).toStrictEqual([{ ...B0, error: ErrorCode.SSH_CLIENT_UNSUPPORTED }]);
  });

  it.skipIf(SSH_ON_PATH === null)(
    "a raw throw of the version read is the net's one row",
    async () => {
      await storeSecret();
      const calls = installSeam(engine, () => DONE, {
        refuseOldClient: () => Promise.reject(new Error("execFile went wrong")),
      });
      const getSecretValue = spyDecrypt();

      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, BOOT),
        ErrorCode.INTERNAL_ERROR,
      );
      expect(err.message).toBe("the use failed unexpectedly");
      expect(getSecretValue).not.toHaveBeenCalled();
      expect(calls).toHaveLength(0);
      expect(useRows()).toStrictEqual([
        {
          detail: { handle: HANDLE, context: "ssh", error: ErrorCode.INTERNAL_ERROR },
          success: false,
        },
      ]);
    },
  );
});

describe.skipIf(SSH_ON_PATH === null)("useSecret — the decrypt and the value's shape", () => {
  it("a handle that came to name another secret is refused", async () => {
    await storeSecret();
    const calls = installSeam(engine);
    const other = randomBytes(18).toString("base64url");
    const manager = internals().secretManager;
    const decrypt = manager.getSecretValue.bind(manager);
    const retained: Uint8Array[] = [];
    manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      await engine.revokeSecret(HANDLE);
      await engine.createSecret({
        name: "pw",
        type: "api_key",
        value: new Uint8Array(Buffer.from(other)),
      });
      const value = await decrypt(...args);
      retained.push(value);
      return value;
    };

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.SECRET_REVOKED,
    );
    expectAbsent(err.message, other);
    expect(calls).toHaveLength(0);
    expect(retained).toHaveLength(1);
    expect(allZero(retained[0] as Uint8Array)).toBe(true);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, error: ErrorCode.SECRET_REVOKED }, success: false },
    ]);
    const newId = await engine.resolveSecretId(HANDLE);
    expect(newId).not.toBe(secretId);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
    expect(store().readBootstrapMark(newId)).toBeUndefined();
  });

  it("a handle that came to name a pending secret is refused as revoked, not with that secret's code", async () => {
    await storeSecret();
    const calls = installSeam(engine);
    const manager = internals().secretManager;
    const decrypt = manager.getSecretValue.bind(manager);
    manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      await engine.revokeSecret(HANDLE);
      await engine.createSecret({ name: "pw", type: "api_key" });
      return decrypt(...args);
    };

    await expectVaultError(() => engine.useSecret(HANDLE, BOOT), ErrorCode.SECRET_REVOKED);

    expect(calls).toHaveLength(0);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, error: ErrorCode.SECRET_REVOKED }, success: false },
    ]);
    const newId = await engine.resolveSecretId(HANDLE);
    expect(store().getSecret(newId)?.status).toBe(SecretStatus.PENDING);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
    expect(store().readBootstrapMark(newId)).toBeUndefined();
  });

  it.each([
    { what: "a line feed", value: (p: string) => Buffer.from(`${p}\n`) },
    { what: "a carriage return", value: (p: string) => Buffer.from(`${p}\rx`) },
    { what: "a NUL byte", value: (p: string) => Buffer.from(`${p}\0x`) },
    { what: "1024 bytes", value: () => Buffer.from(randomBytes(768).toString("base64url")) },
    { what: "empty", value: () => Buffer.alloc(0) },
    {
      what: "no UTF-8 text",
      value: (p: string) => Buffer.concat([Buffer.from(p), Buffer.from([0xc3, 0x28])]),
    },
  ])(
    "a value that cannot be an ssh password is refused after the decrypt, before the mark — $what",
    async ({ value }) => {
      const bytes = value(password);
      await storeSecret(new Uint8Array(bytes));
      const calls = installSeam(engine);
      const retained = retainDecryptedValues(engine);

      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, BOOT),
        ErrorCode.INVALID_SSH_CONFIG,
      );
      expectAbsent(err.message, password);
      expect(err.message).toBe(TEXT.shape);
      expect(calls).toHaveLength(0);
      expect(retained).toHaveLength(1);
      expect(retained[0]?.length).toBe(bytes.length);
      expect(allZero(retained[0] as Uint8Array)).toBe(true);
      expect(useRows()).toStrictEqual([
        { detail: { ...B0, error: ErrorCode.INVALID_SSH_CONFIG }, success: false },
      ]);
      expect(store().readBootstrapMark(secretId)).toBeUndefined();
      expect(statusOf()).toBe(SecretStatus.ACTIVE);
    },
  );

  it("a value of 1023 bytes is served", async () => {
    const value = randomBytes(767).toString("base64url");
    expect(Buffer.byteLength(value)).toBe(1023);
    await storeSecret(new Uint8Array(Buffer.from(value)));
    const seen: string[] = [];
    const calls = installSeam(engine, (call) => {
      seen.push(call.password.toString("utf8"));
      return DONE;
    });

    await expect(engine.useSecret(HANDLE, BOOT)).resolves.toEqual(RESULT);
    expect(calls).toHaveLength(1);
    expect(seen[0] === value).toBe(true);
  });
});

describe.skipIf(SSH_ON_PATH === null)("useSecret — a lock before the claim", () => {
  beforeEach(async () => {
    await storeSecret();
  });

  it.each([{ settles: "accepts" }, { settles: "refuses" }])(
    "a lock during the version read answers VAULT_LOCKED and writes nothing — the client check $settles",
    async ({ settles }) => {
      const entered = deferred<undefined>();
      const gate = deferred<undefined>();
      const calls = installSeam(engine, () => DONE, {
        refuseOldClient: () => {
          entered.resolve(undefined);
          return gate.promise;
        },
      });
      const getSecretValue = spyDecrypt();

      const pending = quiet(engine.useSecret(HANDLE, BOOT));
      await entered.promise;
      await engine.lock();
      const before = nonReadAuditCount(engine);
      if (settles === "accepts") gate.resolve(undefined);
      else gate.reject(FLOOR_REFUSAL);

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      expect(nonReadAuditCount(engine)).toBe(before);
      expect(getSecretValue).not.toHaveBeenCalled();
      expect(calls).toHaveLength(0);
      expect(store().readBootstrapMark(secretId)).toBeUndefined();

      await engine.unlock("password");
      expect(engine.verifyAuditChain().valid).toBe(true);
      const after = installSeam(engine);
      await expect(engine.useSecret(HANDLE, BOOT)).resolves.toStrictEqual(RESULT);
      expect(after).toHaveLength(1);
    },
  );

  it.each([{ when: "before its value" }, { when: "after its value" }])(
    "a lock during the decrypt answers VAULT_LOCKED and writes nothing — $when",
    async ({ when }) => {
      const calls = installSeam(engine);
      const manager = internals().secretManager;
      const decrypt = manager.getSecretValue.bind(manager);
      const retained: Uint8Array[] = [];
      let afterLock = -1;
      manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
        if (when === "before its value") {
          await engine.lock();
          afterLock = nonReadAuditCount(engine);
          return decrypt(...args);
        }
        const value = await decrypt(...args);
        retained.push(value);
        await engine.lock();
        afterLock = nonReadAuditCount(engine);
        return value;
      };

      await expectVaultError(() => engine.useSecret(HANDLE, BOOT), ErrorCode.VAULT_LOCKED);
      expect(nonReadAuditCount(engine)).toBe(afterLock);
      expect(calls).toHaveLength(0);
      expect(store().readBootstrapMark(secretId)).toBeUndefined();
      expect(retained.every(allZero)).toBe(true);

      await engine.unlock("password");
      expect(engine.verifyAuditChain().valid).toBe(true);
      await expect(engine.useSecret(HANDLE, BOOT)).resolves.toStrictEqual(RESULT);
      expect(calls).toHaveLength(1);
    },
  );
});

describe.skipIf(SSH_ON_PATH === null)("useSecret — a bootstrap that reaches the connection", () => {
  it("writes two rows, ends the secret and returns the status", async () => {
    await storeSecret(undefined, { ...POLICY, env_allowlist: ["LANG"] });
    const oldClient = vi.fn(() => Promise.resolve());
    const seen: string[] = [];
    const calls = installSeam(
      engine,
      (call) => {
        seen.push(call.password.toString("utf8"));
        return DONE;
      },
      { refuseOldClient: oldClient },
    );

    const result = await engine.useSecret(HANDLE, BOOT);

    expectAbsent(JSON.stringify(result), password);
    expect(result).toStrictEqual(RESULT);
    expect(oldClient).toHaveBeenCalledWith(SSH_ON_PATH, ["LANG"]);
    expect(calls).toHaveLength(1);
    const call = calls[0] as BootstrapCall;
    expect(seen[0] === password).toBe(true);
    expect(allZero(call.password)).toBe(true);
    expect(call.password.length).toBe(Buffer.byteLength(password));
    expect(call).toMatchObject({
      sshPath: SSH_ON_PATH,
      host: "h1.example",
      port: 22,
      user: "ubuntu",
      sudoers: false,
      budgetMs: 120_000,
    });
    expect(call.installKey).toEqual(parseSshPublicKey(KEY_A, SSH_INSTALL_KEY_TYPES));
    expect(call.hostKeys).toEqual([parseSshPublicKey(HOST_KEY, SSH_HOST_KEY_TYPES)]);
    expect(call.policy).toEqual(await engine.getInjectionPolicy(HANDLE));

    const uses = useRows();
    expectAbsent(JSON.stringify(uses), password);
    expect(uses).toStrictEqual([
      { detail: { ...B0, began: true }, success: true },
      {
        detail: {
          ...B0,
          outcome: "done",
          key: "installed",
          drop_in: "not_asked",
          secret_ended: true,
          ...SPAWN,
        },
        success: true,
      },
    ]);
    const revokes = rowsOf(AuditEventType.SECRET_REVOKE);
    expect(revokes.map((row) => ({ detail: row.detail, success: row.success }))).toStrictEqual([
      { detail: { handle: HANDLE, reason: "ssh_bootstrap" }, success: true },
    ]);
    expect(statusOf()).toBe(SecretStatus.REVOKED);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();

    await expectVaultError(() => engine.useSecret(HANDLE, BOOT), ErrorCode.SECRET_REVOKED);
    expect(calls).toHaveLength(1);
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("the second listed key, with the sudoers flag, reaches the call as the block holds it", async () => {
    await storeSecret();
    const calls = installSeam(engine, () => ({
      kind: "done",
      key: "present",
      sudoers: "written",
      spawn: SPAWN,
    }));

    await expect(
      engine.useSecret(HANDLE, boot({ public_key: KEY_B, sudoers: true })),
    ).resolves.toStrictEqual({ type: "ssh_bootstrap", key: "present", sudoers: "written" });

    expect(calls[0]?.installKey).toEqual(parseSshPublicKey(KEY_B, SSH_INSTALL_KEY_TYPES));
    expect(calls[0]?.sudoers).toBe(true);
    const fingerprint = SSH_PUBLIC_KEY_VECTORS.find((v) => v.line === KEY_B)?.fingerprint;
    expect(useDetails().at(-1)).toStrictEqual({
      ...B0,
      key_fingerprint: fingerprint,
      sudoers: true,
      outcome: "done",
      key: "present",
      drop_in: "written",
      secret_ended: true,
      ...SPAWN,
    });
  });

  it("the mark is committed before the spawn", async () => {
    await storeSecret();
    const inside: { mark: unknown; uses: unknown }[] = [];
    installSeam(engine, () => {
      inside.push({ mark: store().readBootstrapMark(secretId), uses: useDetails() });
      return DONE;
    });
    const before = Date.now();

    await engine.useSecret(HANDLE, BOOT);

    expect(inside).toHaveLength(1);
    const mark = inside[0]?.mark as { claim: string; at: number };
    expect(mark.claim).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(mark.at).toBeGreaterThanOrEqual(before);
    expect(inside[0]?.uses).toStrictEqual([{ ...B0, began: true }]);
  });

  it.each([
    {
      what: "refused: the password",
      outcome: {
        kind: "refused",
        error: VaultError.sshPasswordRefused(),
        spawn: SPAWN,
      } as BootstrapOutcome,
      row: {
        outcome: "refused",
        error: ErrorCode.SSH_PASSWORD_REFUSED,
        secret_ended: false,
        ...SPAWN,
      },
      ends: false,
    },
    {
      what: "refused: a failed step",
      outcome: {
        kind: "refused",
        error: VaultError.sshBootstrapStepFailed("refused", "not_attempted"),
        status: { dropIn: "refused", key: "not_attempted" },
        spawn: SPAWN,
      } as BootstrapOutcome,
      row: {
        outcome: "refused",
        error: ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
        drop_in: "refused",
        key: "not_attempted",
        secret_ended: false,
        ...SPAWN,
      },
      ends: false,
    },
    {
      what: "unconfirmed",
      outcome: { kind: "unconfirmed", spawn: SPAWN } as BootstrapOutcome,
      row: {
        outcome: "unconfirmed",
        error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
        secret_ended: true,
        ...SPAWN,
      },
      ends: true,
    },
    {
      what: "not spawned: the seam refused the isolation",
      outcome: {
        kind: "not_spawned",
        error: VaultError.networkIsolationUnavailable("no network namespace on this host"),
        spawn: { network_isolation: true, fs_isolation: false },
      } as BootstrapOutcome,
      row: {
        outcome: "not_spawned",
        error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
        secret_ended: false,
        network_isolation: true,
        fs_isolation: false,
      },
      ends: false,
    },
    {
      what: "not spawned: before the seam",
      outcome: {
        kind: "not_spawned",
        error: new VaultError(
          ErrorCode.FILE_IO_ERROR,
          "a temporary file of the ssh bootstrap could not be prepared",
        ),
      } as BootstrapOutcome,
      row: { outcome: "not_spawned", error: ErrorCode.FILE_IO_ERROR, secret_ended: false },
      ends: false,
    },
  ])("each outcome — $what", async ({ outcome, row, ends }) => {
    await storeSecret();
    const calls = installSeam(engine, () => outcome);

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ends ? ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED : (outcome as { error: VaultError }).error.code,
    );
    expectAbsent(err.message, password);
    expect(err.message).toBe(
      ends ? TEXT.unconfirmed : (outcome as { error: VaultError }).error.message,
    );
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, began: true }, success: true },
      { detail: { ...B0, ...row }, success: false },
    ]);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
    if (ends) {
      expect(statusOf()).toBe(SecretStatus.REVOKED);
      expect(revokeDetails()).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
      return;
    }
    expect(statusOf()).toBe(SecretStatus.ACTIVE);
    expect(revokeDetails()).toStrictEqual([]);
    installSeam(engine);
    await expect(engine.useSecret(HANDLE, BOOT)).resolves.toStrictEqual(RESULT);
    expect(calls).toHaveLength(1);
  });

  it("the outcome's row takes the seam's eleven fields by name, last: a field of another name neither overwrites nor joins the engine's", async () => {
    await storeSecret();
    const eleven = {
      exit_code: 255,
      timed_out: true,
      truncated: true,
      network_isolation: true,
      isolation_mechanism: "unshare",
      fs_isolation: true,
      fs_isolation_mechanism: "landlock",
      sanitized: true,
      descendant_sweep: { killed: 1, failed: false },
      tree_kill: "job",
      strict_tree_exit: true,
    };
    installSeam(
      engine,
      () =>
        ({
          kind: "refused",
          error: VaultError.sshPasswordRefused(),
          spawn: {
            outcome: "done",
            error: "NONE",
            secret_ended: true,
            host: "elsewhere.example",
            key_fingerprint: "SHA256:forged",
            key: "installed",
            drop_in: "written",
            mark: "gone",
            stdout: "a line of the host",
            ...eleven,
          },
        }) as unknown as BootstrapOutcome,
    );

    await expectVaultError(() => engine.useSecret(HANDLE, BOOT), ErrorCode.SSH_PASSWORD_REFUSED);

    const detail = useDetails().at(-1);
    expect(detail).toStrictEqual({
      ...B0,
      outcome: "refused",
      error: ErrorCode.SSH_PASSWORD_REFUSED,
      secret_ended: false,
      ...eleven,
    });
    expect(Object.keys(detail as object)).toStrictEqual([
      ...Object.keys(B0),
      "outcome",
      "error",
      "secret_ended",
      ...Object.keys(eleven),
    ]);
  });

  it("an outcome of a kind the engine does not know ends the secret", async () => {
    await storeSecret();
    installSeam(engine, () => ({ kind: "later", spawn: SPAWN }) as unknown as BootstrapOutcome);

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
    );
    expect(err.message).toBe(TEXT.unconfirmed);
    expect(useRows().at(-1)).toStrictEqual({
      detail: {
        ...B0,
        outcome: "later",
        error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
        secret_ended: true,
        ...SPAWN,
      },
      success: false,
    });
    expect(statusOf()).toBe(SecretStatus.REVOKED);
    expect(revokeDetails()).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
  });

  it("the end asks no revoke grant and ends the child", async () => {
    await storeSecret();
    registerAgents(engine, "alice");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alice", permissions: ["use"] },
      "test-admin",
    );
    const alice: CallerContext = {
      principal_type: "agent",
      principal_id: "alice",
      interface: "rest",
    };
    await seedLiveStdioEntry(engine, secretId);
    installSeam(engine);

    await expect(engine.useSecret(HANDLE, BOOT, alice)).resolves.toStrictEqual(RESULT);

    const uses = rowsOf(AuditEventType.SECRET_USE);
    expect(uses).toHaveLength(2);
    for (const use of uses) {
      expect(use).toMatchObject({ principal_type: "agent", principal_id: "alice" });
      expect(use.detail).toMatchObject({ interface: "rest" });
    }
    const revokes = rowsOf(AuditEventType.SECRET_REVOKE);
    expect(revokes).toHaveLength(1);
    expect(revokes[0]).toMatchObject({
      success: true,
      principal_type: "agent",
      principal_id: "alice",
    });
    expect(revokes[0]?.detail).toStrictEqual({
      handle: HANDLE,
      reason: "ssh_bootstrap",
      interface: "rest",
    });
    expect(registryOf(engine).get(secretId)).toBeUndefined();
    const terminates = rowsOf(AuditEventType.MCP_TERMINATE);
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail).toMatchObject({ reason: "secret_revoked", server: "docs" });
  });
});

describe.skipIf(SSH_ON_PATH === null)(
  "useSecret — an outcome that is not recorded, and the use after it",
  () => {
    /** Starts a bootstrap whose `run` waits; resolves once the call is inside `run`. */
    async function startWaiting(): Promise<{
      pending: Promise<unknown>;
      settle: (outcome: BootstrapOutcome) => void;
      fail: (reason: unknown) => void;
      calls: BootstrapCall[];
      markAt: number;
    }> {
      const gate = deferred<BootstrapOutcome>();
      const entered = deferred<undefined>();
      const calls = installSeam(engine, () => {
        entered.resolve(undefined);
        return gate.promise;
      });
      const pending = quiet(engine.useSecret(HANDLE, BOOT));
      await entered.promise;
      const mark = store().readBootstrapMark(secretId);
      expect(mark).toBeDefined();
      return {
        pending,
        settle: gate.resolve,
        fail: gate.reject,
        calls,
        markAt: (mark as { at: number }).at,
      };
    }

    function expectBeganAlone(extra: Record<string, unknown>[] = []): void {
      expect(useDetails()).toStrictEqual([{ ...B0, began: true }, ...extra]);
      expect(revokeDetails()).toStrictEqual([]);
      expect(statusOf()).toBe(SecretStatus.ACTIVE);
    }

    beforeEach(async () => {
      await storeSecret();
    });

    it("the engine locked while the session ran", async () => {
      const { pending, settle, calls, markAt } = await startWaiting();
      await engine.lock();
      settle(DONE);

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      expect(allZero((calls[0] as BootstrapCall).password)).toBe(true);
      await engine.unlock("password");
      expect(engine.verifyAuditChain().valid).toBe(true);
      expectBeganAlone();
      expect(store().readBootstrapMark(secretId)?.at).toBe(markAt);

      await expectEndedAtNextUse(engine, markAt);
      expect(engine.verifyAuditChain().valid).toBe(true);
    });

    it("locked and unlocked again", async () => {
      const { pending, settle, markAt } = await startWaiting();
      await engine.lock();
      await engine.unlock("password");
      const before = nonReadAuditCount(engine);
      settle(DONE);

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      expect(nonReadAuditCount(engine)).toBe(before);
      expectBeganAlone();
      expect(store().readBootstrapMark(secretId)?.at).toBe(markAt);

      await expectEndedAtNextUse(engine, markAt);
    });

    it("unlocked again over the live engine", async () => {
      const { pending, settle, markAt } = await startWaiting();
      await engine.unlock("password");
      const before = nonReadAuditCount(engine);
      settle(DONE);

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      expect(nonReadAuditCount(engine)).toBe(before);
      expectBeganAlone();
      expect(store().readBootstrapMark(secretId)?.at).toBe(markAt);

      await expectEndedAtNextUse(engine, markAt);
    });

    it("the outcome settling while lock() still waits answers VAULT_LOCKED", async () => {
      const closing = deferred<undefined>();
      const closeGate = deferred<undefined>();
      await seedLiveStdioEntry(engine, secretId, () => {
        closing.resolve(undefined);
        return closeGate.promise;
      });
      const { pending, settle, markAt } = await startWaiting();
      const locking = engine.lock();
      await closing.promise;
      const before = nonReadAuditCount(engine);
      settle(DONE);

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      expect(nonReadAuditCount(engine)).toBe(before);
      closeGate.resolve(undefined);
      await locking;
      await engine.unlock("password");
      expect(engine.verifyAuditChain().valid).toBe(true);
      expectBeganAlone();
      expect(store().readBootstrapMark(secretId)?.at).toBe(markAt);

      await expectEndedAtNextUse(engine, markAt);
    });

    it("a VaultError out of run under the call's keys writes its row; the mark stays", async () => {
      const calls = installSeam(engine, () => {
        throw VaultError.sshConnectFailed();
      });

      await expectVaultError(() => engine.useSecret(HANDLE, BOOT), ErrorCode.SSH_CONNECT_FAILED);

      expect(calls).toHaveLength(1);
      expect(useRows().at(-1)).toStrictEqual({
        detail: { ...B0, error: ErrorCode.SSH_CONNECT_FAILED },
        success: false,
      });
      expectBeganAlone([{ ...B0, error: ErrorCode.SSH_CONNECT_FAILED }]);
      expect(internals().bootstrapHolds.has(secretId)).toBe(false);
      const mark = store().readBootstrapMark(secretId);
      expect(mark).toBeDefined();

      await expectEndedAtNextUse(engine, (mark as { at: number }).at);
    });

    it("run throwing after a lock answers VAULT_LOCKED and writes nothing", async () => {
      const { pending, fail, markAt } = await startWaiting();
      await engine.lock();
      const before = nonReadAuditCount(engine);
      fail(new Error("the seam broke"));

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      expect(nonReadAuditCount(engine)).toBe(before);
      await engine.unlock("password");
      expect(engine.verifyAuditChain().valid).toBe(true);
      expectBeganAlone();

      await expectEndedAtNextUse(engine, markAt);
    });

    it("destroyed", async () => {
      const { pending, settle, markAt } = await startWaiting();
      await engine.destroy();
      settle(DONE);

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      second = new VaultEngine({ dbPath, sessionPath: join(tempDir, "other-session.json") });
      await second.unlock("password");
      expect(useDetails(second)).toStrictEqual([{ ...B0, began: true }]);
      expect(statusOf(second)).toBe(SecretStatus.ACTIVE);

      await expectEndedAtNextUse(second, markAt);
    });

    it.each([
      { failing: "its first row", nth: 1 },
      { failing: "its second row", nth: 2 },
    ])("the outcome's commit failing — $failing", async ({ nth }) => {
      const calls = installSeam(engine, () => {
        failAuditInsert(nth);
        return DONE;
      });

      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, BOOT),
        ErrorCode.INTERNAL_ERROR,
      );
      expectAbsent(err.message, password);
      vi.restoreAllMocks();
      expect(calls).toHaveLength(1);
      expectBeganAlone([{ handle: HANDLE, context: "ssh", error: ErrorCode.INTERNAL_ERROR }]);
      const mark = store().readBootstrapMark(secretId);
      expect(mark).toBeDefined();

      await expectEndedAtNextUse(engine, (mark as { at: number }).at);
      expect(engine.verifyAuditChain().valid).toBe(true);
    });

    it("run throwing", async () => {
      const calls = installSeam(engine, () => {
        throw new Error("the seam broke");
      });

      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, BOOT),
        ErrorCode.INTERNAL_ERROR,
      );
      expect(err.message).toBe("the injection context failed unexpectedly");
      expect(calls).toHaveLength(1);
      expect(allZero((calls[0] as BootstrapCall).password)).toBe(true);
      expectBeganAlone([{ handle: HANDLE, context: "ssh", error: ErrorCode.INTERNAL_ERROR }]);
      expect(internals().bootstrapHolds.has(secretId)).toBe(false);
      const mark = store().readBootstrapMark(secretId);
      expect(mark).toBeDefined();

      await expectEndedAtNextUse(engine, (mark as { at: number }).at);
    });

    it("the mark's commit failing spawns nothing", async () => {
      const calls = installSeam(engine);
      failAuditInsert(1);

      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, BOOT),
        ErrorCode.INTERNAL_ERROR,
      );
      expectAbsent(err.message, password);
      vi.restoreAllMocks();
      expect(calls).toHaveLength(0);
      expect(useDetails()).toStrictEqual([
        { handle: HANDLE, context: "ssh", error: ErrorCode.INTERNAL_ERROR },
      ]);
      expect(store().readBootstrapMark(secretId)).toBeUndefined();
      expect(statusOf()).toBe(SecretStatus.ACTIVE);
      expect(internals().bootstrapHolds.has(secretId)).toBe(false);

      await expect(engine.useSecret(HANDLE, BOOT)).resolves.toStrictEqual(RESULT);
      expect(calls).toHaveLength(1);
    });
  },
);

describe.skipIf(SSH_ON_PATH === null)("useSecret — two bootstraps of one secret", () => {
  beforeEach(async () => {
    await storeSecret();
  });

  it("two calls sent in one tick: one runs, the other is in flight", async () => {
    const retained = retainDecryptedValues(engine);

    const { calls, settled } = await twoInOneTick();

    expect(calls).toHaveLength(1);
    const fulfilled = settled.filter((s) => s.status === "fulfilled");
    const rejected = settled.filter((s) => s.status === "rejected");
    expect(fulfilled.map((s) => s.value)).toStrictEqual([RESULT]);
    expect(rejected).toHaveLength(1);
    const err = (rejected[0] as PromiseRejectedResult).reason as VaultError;
    expect(err.code).toBe(ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT);
    expect(err.message).toBe(TEXT.inFlight);
    expect(retained).toHaveLength(2);
    expect(retained.every(allZero)).toBe(true);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, began: true }, success: true },
      { detail: { ...B0, error: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT }, success: false },
      {
        detail: {
          ...B0,
          outcome: "done",
          key: "installed",
          drop_in: "not_asked",
          secret_ended: true,
          ...SPAWN,
        },
        success: true,
      },
    ]);
    expect(revokeDetails()).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
  });

  it("a call while the first runs is refused before its decrypt", async () => {
    const gate = deferred<BootstrapOutcome>();
    const entered = deferred<undefined>();
    const calls = installSeam(engine, () => {
      entered.resolve(undefined);
      return gate.promise;
    });
    const getSecretValue = spyDecrypt();

    const first = quiet(engine.useSecret(HANDLE, BOOT));
    await entered.promise;
    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, BOOT),
      ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
    );
    expect(err.message).toBe(TEXT.inFlight);
    expect(getSecretValue).toHaveBeenCalledTimes(1);
    expect(statusOf()).toBe(SecretStatus.ACTIVE);
    gate.resolve(DONE);

    await expect(first).resolves.toStrictEqual(RESULT);
    expect(calls).toHaveLength(1);
    expect(useDetails()).toStrictEqual([
      { ...B0, began: true },
      { ...B0, error: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT },
      {
        ...B0,
        outcome: "done",
        key: "installed",
        drop_in: "not_asked",
        secret_ended: true,
        ...SPAWN,
      },
    ]);
  });

  it("two uses of a marked secret in one tick: one ends it, the other finds it revoked", async () => {
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);
    const calls = installSeam(engine);
    const retained = retainDecryptedValues(engine);

    const settled = await Promise.allSettled([
      engine.useSecret(HANDLE, BOOT),
      engine.useSecret(HANDLE, BOOT),
    ]);

    const codes = settled.map((s) =>
      s.status === "rejected" ? (s.reason as VaultError).code : "fulfilled",
    );
    expect(codes.sort()).toStrictEqual(
      [ErrorCode.SECRET_REVOKED, ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED].sort(),
    );
    expect(calls).toHaveLength(0);
    expect(retained).toHaveLength(0);
    expect(revokeDetails()).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
    expect(statusOf()).toBe(SecretStatus.REVOKED);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
  });
});

describe.skipIf(SSH_ON_PATH === null)("useSecret — two engines on one vault", () => {
  const DONE_ROW_GONE = {
    ...B0,
    outcome: "done",
    key: "installed",
    drop_in: "not_asked",
    secret_ended: false,
    mark: "gone",
    ...SPAWN,
  };

  beforeEach(async () => {
    await storeSecret();
    second = new VaultEngine({ dbPath, sessionPath: join(tempDir, "other-session.json") });
    await second.unlock("password");
  });

  it("the second engine's call ends the secret under the first's running call", async () => {
    const other = second as VaultEngine;
    const gate = deferred<BootstrapOutcome>();
    const entered = deferred<undefined>();
    const callsA = installSeam(engine, () => {
      entered.resolve(undefined);
      return gate.promise;
    });
    const callsB = installSeam(other);
    const getB = spyDecrypt(other);

    const pendingA = quiet(engine.useSecret(HANDLE, BOOT));
    await entered.promise;
    const markAt = (store().readBootstrapMark(secretId) as { at: number }).at;
    const err = await expectVaultError(
      () => other.useSecret(HANDLE, BOOT),
      ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
    );
    expect(err.message).toBe(TEXT.unconfirmed);
    expect(callsB).toHaveLength(0);
    expect(getB).not.toHaveBeenCalled();
    gate.resolve(DONE);

    await expect(pendingA).resolves.toStrictEqual(RESULT);
    expect(callsA).toHaveLength(1);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, began: true }, success: true },
      {
        detail: {
          ...B0,
          error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
          secret_ended: true,
          mark_at: markAt,
        },
        success: false,
      },
      { detail: DONE_ROW_GONE, success: true },
    ]);
    expect(revokeDetails()).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
  });

  it("a second engine that passed its checks first fails at its claim", async () => {
    const other = second as VaultEngine;
    const gate = deferred<BootstrapOutcome>();
    const bWaits = deferred<undefined>();
    const aRuns = deferred<undefined>();
    const callsB = installSeam(other, () => DONE, {
      refuseOldClient: () => {
        bWaits.resolve(undefined);
        return aRuns.promise;
      },
    });
    const retainedB = retainDecryptedValues(other);

    const pendingB = quiet(other.useSecret(HANDLE, BOOT));
    await bWaits.promise;
    const callsA = installSeam(engine, () => {
      aRuns.resolve(undefined);
      return gate.promise;
    });
    const pendingA = quiet(engine.useSecret(HANDLE, BOOT));

    const err = await expectVaultError(() => pendingB, ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED);
    expect(err.message).toBe(TEXT.unconfirmed);
    expect(callsB).toHaveLength(0);
    expect(retainedB).toHaveLength(1);
    expect(allZero(retainedB[0] as Uint8Array)).toBe(true);
    gate.resolve(DONE);

    await expect(pendingA).resolves.toStrictEqual(RESULT);
    expect(callsA).toHaveLength(1);
    const details = useDetails();
    expect(details).toHaveLength(3);
    expect(details[0]).toStrictEqual({ ...B0, began: true });
    expect(details[1]).toMatchObject({
      ...B0,
      error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      secret_ended: true,
    });
    expect(details[2]).toStrictEqual(DONE_ROW_GONE);
    expect(revokeDetails()).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
  });

  it("the claim's refusal ends the secret's live child, as the status ladder does", async () => {
    const other = second as VaultEngine;
    await seedLiveStdioEntry(engine, secretId);
    const calls = installSeam(engine);
    const manager = internals().secretManager;
    const decrypt = manager.getSecretValue.bind(manager);
    manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      const value = await decrypt(...args);
      await other.revokeSecret(HANDLE);
      return value;
    };

    await expectVaultError(() => engine.useSecret(HANDLE, BOOT), ErrorCode.SECRET_REVOKED);

    expect(calls).toHaveLength(0);
    expect(useDetails()).toStrictEqual([{ ...B0, error: ErrorCode.SECRET_REVOKED }]);
    expect(registryOf(engine).get(secretId)).toBeUndefined();
    const terminates = rowsOf(AuditEventType.MCP_TERMINATE);
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail).toMatchObject({ reason: "secret_unusable", server: "docs" });
  });

  it("the claim reads the status again", async () => {
    const other = second as VaultEngine;
    installSeam(engine);
    const callsB = installSeam(other);
    const manager = internals(other).secretManager;
    const decrypt = manager.getSecretValue.bind(manager);
    const retainedB: Uint8Array[] = [];
    manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      const value = await decrypt(...args);
      retainedB.push(value);
      await engine.useSecret(HANDLE, BOOT);
      return value;
    };

    const err = await expectVaultError(
      () => other.useSecret(HANDLE, BOOT),
      ErrorCode.SECRET_REVOKED,
    );
    expectAbsent(err.message, password);
    expect(callsB).toHaveLength(0);
    expect(allZero(retainedB[0] as Uint8Array)).toBe(true);
    expect(useRows()).toStrictEqual([
      { detail: { ...B0, began: true }, success: true },
      {
        detail: {
          ...B0,
          outcome: "done",
          key: "installed",
          drop_in: "not_asked",
          secret_ended: true,
          ...SPAWN,
        },
        success: true,
      },
      { detail: { ...B0, error: ErrorCode.SECRET_REVOKED }, success: false },
    ]);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
  });
});

describe.skipIf(SSH_ON_PATH === null)(
  "useSecret — an administrator's write under a running call (Review Focus 2)",
  () => {
    beforeEach(async () => {
      await storeSecret();
    });

    it("the secret revoked (secret delete): recorded once, ended once, the mark cleared", async () => {
      installSeam(engine, async () => {
        await engine.revokeSecret(HANDLE);
        return DONE;
      });

      await expect(engine.useSecret(HANDLE, BOOT)).resolves.toStrictEqual(RESULT);

      expect(useDetails()).toStrictEqual([
        { ...B0, began: true },
        {
          ...B0,
          outcome: "done",
          key: "installed",
          drop_in: "not_asked",
          secret_ended: false,
          mark: "gone",
          ...SPAWN,
        },
      ]);
      expect(revokeDetails()).toStrictEqual([{ handle: HANDLE }]);
      expect(statusOf()).toBe(SecretStatus.REVOKED);
      expect(store().readBootstrapMark(secretId)).toBeUndefined();
      expect(store().getMeta(`ssh_bootstrap_mark:${secretId}`)).toBeUndefined();
    });

    it("a policy without the block: the call that began under it is recorded as it began", async () => {
      installSeam(engine, async () => {
        await engine.setInjectionPolicy(HANDLE, { command_allowlist: ["ssh"] });
        return DONE;
      });

      await expect(engine.useSecret(HANDLE, BOOT)).resolves.toStrictEqual(RESULT);

      expect((await engine.getInjectionPolicy(HANDLE)).ssh_bootstrap).toBeNull();
      expect(useDetails()).toStrictEqual([
        { ...B0, began: true },
        {
          ...B0,
          outcome: "done",
          key: "installed",
          drop_in: "not_asked",
          secret_ended: true,
          ...SPAWN,
        },
      ]);
      expect(revokeDetails()).toStrictEqual([{ handle: HANDLE, reason: "ssh_bootstrap" }]);
      expect(statusOf()).toBe(SecretStatus.REVOKED);
      expect(store().readBootstrapMark(secretId)).toBeUndefined();
    });
  },
);

describe.skipIf(SSH_ON_PATH === null)(
  "useSecret — a password that is part of the bootstrap's own messages",
  () => {
    const answering = (outcome: BootstrapOutcome) => (): Promise<unknown> => {
      installSeam(engine, () => outcome);
      return engine.useSecret(HANDLE, BOOT);
    };
    const throwing = (failedRow: boolean) => (): Promise<unknown> => {
      installSeam(engine, () => {
        if (failedRow) failAuditInsert(1);
        throw new Error("the seam broke");
      });
      return engine.useSecret(HANDLE, BOOT);
    };
    const lostClaim = async (): Promise<unknown> => {
      const { settled } = await twoInOneTick();
      throw (settled.find((s) => s.status === "rejected") as PromiseRejectedResult).reason;
    };
    const revokedBeforeClaim = (): Promise<unknown> => {
      installSeam(engine);
      const manager = internals().secretManager;
      const decrypt = manager.getSecretValue.bind(manager);
      manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
        const value = await decrypt(...args);
        await engine.revokeSecret(HANDLE);
        return value;
      };
      return engine.useSecret(HANDLE, BOOT);
    };
    const stepFailed: BootstrapOutcome = {
      kind: "refused",
      error: VaultError.sshBootstrapStepFailed("refused", "not_attempted"),
      status: { dropIn: "refused", key: "not_attempted" },
      spawn: SPAWN,
    };
    const passwordRefused: BootstrapOutcome = {
      kind: "refused",
      error: VaultError.sshPasswordRefused(),
      spawn: SPAWN,
    };
    const unconfirmed: BootstrapOutcome = { kind: "unconfirmed", spawn: SPAWN };
    const word = "a word of the message";
    const letter = "a letter of the message";

    it.each([
      {
        what: "the in-flight refusal at the claim",
        is: word,
        stored: WORD_SECRET,
        use: lostClaim,
        code: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
        text: TEXT.inFlight,
      },
      {
        what: "the in-flight refusal at the claim",
        is: letter,
        stored: LETTER,
        use: lostClaim,
        code: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
        text: TEXT.inFlight,
      },
      {
        what: "an unconfirmed outcome",
        is: word,
        stored: WORD_SECRET,
        use: answering(unconfirmed),
        code: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
        text: TEXT.unconfirmed,
      },
      {
        what: "an unconfirmed outcome",
        is: letter,
        stored: LETTER,
        use: answering(unconfirmed),
        code: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
        text: TEXT.unconfirmed,
      },
      {
        what: "a failed step",
        is: word,
        stored: WORD_KEY,
        use: answering(stepFailed),
        code: ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
        text: TEXT.stepFailed,
      },
      {
        what: "a failed step",
        is: letter,
        stored: LETTER,
        use: answering(stepFailed),
        code: ErrorCode.SSH_BOOTSTRAP_STEP_FAILED,
        text: TEXT.stepFailed,
      },
      {
        what: "a refused password",
        is: word,
        stored: WORD_PASSWORD,
        use: answering(passwordRefused),
        code: ErrorCode.SSH_PASSWORD_REFUSED,
        text: TEXT.passwordRefused,
      },
      {
        what: "a refused password",
        is: letter,
        stored: LETTER,
        use: answering(passwordRefused),
        code: ErrorCode.SSH_PASSWORD_REFUSED,
        text: TEXT.passwordRefused,
      },
      {
        what: "the value's shape",
        is: `${word} before a line feed`,
        stored: `${WORD_PASSWORD}\n`,
        use: answering(DONE),
        code: ErrorCode.INVALID_SSH_CONFIG,
        text: TEXT.shape,
      },
      {
        what: "the value's shape",
        is: `${letter} before a line feed`,
        stored: `${LETTER}\n`,
        use: answering(DONE),
        code: ErrorCode.INVALID_SSH_CONFIG,
        text: TEXT.shape,
      },
      {
        what: "the secret revoked before the claim",
        is: "the scheme of its handle",
        stored: WORD_SECRET,
        use: revokedBeforeClaim,
        code: ErrorCode.SECRET_REVOKED,
        text: TEXT.revoked,
      },
      {
        what: "a throw of the seam that is no VaultError",
        is: letter,
        stored: LETTER,
        use: throwing(false),
        code: ErrorCode.INTERNAL_ERROR,
        text: TEXT.internal,
      },
      {
        what: "a throw of the seam whose row cannot be written",
        is: letter,
        stored: LETTER,
        use: throwing(true),
        code: ErrorCode.INTERNAL_ERROR,
        text: TEXT.auditFailed,
      },
    ])(
      "$what reads letter for letter — the password is $is",
      async ({ stored, use, code, text }) => {
        await storeSecret(new Uint8Array(Buffer.from(stored)));

        const err = await expectVaultError(use, code);

        expect(err.message).toBe(text);
      },
    );
  },
);

describe("useSecret — the ssh action's two shapes", () => {
  it("the ssh action without operation is served as before", async () => {
    await storeSecret(undefined, { command_allowlist: ["ssh"] });
    const seen: { action: unknown; value: string }[] = [];
    const sshResult = { type: "ssh", exit_code: 0, stdout: "", stderr: "" };
    internals().sshInjector = {
      executeWithSecret: (...args: unknown[]) => {
        seen.push({ action: args[0], value: Buffer.from(args[1] as Uint8Array).toString("utf8") });
        return Promise.resolve(sshResult);
      },
    };
    const calls = installSeam(engine);
    const action = unparsed({ type: "ssh", host: "h1.example", user: "ubuntu", command: "uptime" });

    await expect(engine.useSecret(HANDLE, action)).resolves.toBe(sshResult);

    expect(seen).toHaveLength(1);
    expect(seen[0]?.action).toStrictEqual(action);
    expect(seen[0]?.value === password).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("a 10 000-character host is refused at the door without a row", async () => {
    await storeSecret();
    const calls = installSeam(engine);
    const before = nonReadAuditCount(engine);

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, boot({ host: "h".repeat(10_000) })),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(
      "an ssh bootstrap's host and user must be names of letters, digits, '.', '_' and '-'",
    );
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(calls).toHaveLength(0);
  });

  it("an operation that answers the door absent and the engine bootstrap is no bootstrap: its first answer holds and the block refuses it", async () => {
    await storeSecret();
    const commandInjector = vi.fn(() => Promise.resolve({ type: "ssh" }));
    internals().sshInjector = { executeWithSecret: commandInjector };
    const calls = installSeam(engine);
    const getSecretValue = spyDecrypt();
    let operationReads = 0;
    const commandReads: string[] = [];
    const action = {
      type: "ssh",
      host: "h1.example",
      user: "ubuntu",
      public_key: KEY_A,
      get operation(): string | undefined {
        operationReads += 1;
        return operationReads === 2 ? "bootstrap" : undefined;
      },
      get command(): string {
        commandReads.push("command");
        return "id";
      },
      get timeout_ms(): number {
        commandReads.push("timeout_ms");
        return 1000;
      },
    };

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, unparsed(action)),
      ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED,
    );

    expect(err.message).toBe(
      "Use refused: the secret holds an ssh bootstrap block and serves the ssh bootstrap alone",
    );
    expect(operationReads).toBe(1);
    expect(commandReads).toStrictEqual(["command", "timeout_ms"]);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expect(commandInjector).not.toHaveBeenCalled();
    expect(useDetails()).toStrictEqual([
      { handle: HANDLE, context: "ssh", error: ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED },
    ]);
  });

  it("an operation that answers the door bootstrap and then absent is refused at the door as the bootstrap it first read", async () => {
    await storeSecret();
    const commandInjector = vi.fn(() => Promise.resolve({ type: "ssh" }));
    internals().sshInjector = { executeWithSecret: commandInjector };
    const calls = installSeam(engine);
    const getSecretValue = spyDecrypt();
    let operationReads = 0;
    const action = {
      type: "ssh",
      host: "h1.example",
      user: "ubuntu",
      public_key: KEY_A,
      command: "id",
      get operation(): string | undefined {
        operationReads += 1;
        return operationReads === 1 ? "bootstrap" : undefined;
      },
    };
    const before = nonReadAuditCount(engine);

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, unparsed(action)),
      ErrorCode.INVALID_INPUT,
    );

    expect(err.message).toBe(
      "an ssh bootstrap takes type, operation, host, user, port, public_key and sudoers alone",
    );
    expect(operationReads).toBe(1);
    expect(nonReadAuditCount(engine)).toBe(before);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(commandInjector).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });
});
