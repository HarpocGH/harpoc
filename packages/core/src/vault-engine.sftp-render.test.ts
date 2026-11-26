import { randomBytes, randomInt } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  CallerContext,
  InjectionPolicy,
  InjectionPolicyInput,
  RateLimiter,
  RenderEntry,
  UseSecretAction,
} from "@harpoc/shared";
import {
  AuditEventType,
  ErrorCode,
  injectionPolicyInputSchema,
  PrincipalType,
  VaultError,
} from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import {
  installRenderSeam,
  nonReadAuditCount,
  registerAgents,
  registryOf,
  retainDecryptedValues,
  storeInjectionPolicyBlob,
} from "./__fixtures__/engine-seams.js";
import { resolveNativeSshClient } from "./injection/__fixtures__/native-ssh-client.js";
import { approval, ENTRY, ENTRY_ONE, keyPolicy } from "./injection/__fixtures__/render-entries.js";
import { BLOCK, BOOT } from "./injection/__fixtures__/ssh-public-keys.js";
import { controlledPathDirs } from "./injection/allowlist.js";
import type { RenderPlan, RenderRun } from "./injection/sftp-render.js";
import { runRender } from "./injection/sftp-render.js";
import { EphemeralSshAgent } from "./injection/ssh-agent/index.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import type { SftpRenderSeam, SshBootstrapSeam } from "./vault-engine.js";
import { VaultEngine } from "./vault-engine.js";
import { system32Path } from "./win32-paths.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// From step 2.3 on a render resolves `ssh` as the product does; on Windows only the native
// Win32-OpenSSH client is accepted, so its directory leads the PATH. A host without one skips.
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}
const SSH = resolveNativeSshClient("ssh");
const itSsh = it.skipIf(SSH === null);

const KEY = "secret://deploy-key";
const BOT = "secret://bot-token";
const API = "secret://api-key";
const DB = "secret://db-pass";
const SLOTS = [BOT, API, DB];
const RESULT = { type: "sftp_render", status: "written" };
const ISO = { network_isolation: false, fs_isolation: false };
const REST = { interface: "rest" };
const R0 = { context: "sftp", operation: "render" };
const R = {
  context: "sftp",
  host: "h1.example",
  port: 22,
  user: "deploy",
  operation: "render",
  entry: "env",
  remote_path: "/srv/app/.env",
};
const S = {
  context: "sftp",
  operation: "render",
  entry: "env",
  key: KEY,
  host: "h1.example",
  port: 22,
  user: "deploy",
  remote_path: "/srv/app/.env",
};
const MIXED_CLASS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=:@%-";

const TEXT = {
  forbidden: "an sftp render takes no host, user, port, remote_path or local_path",
  timeout: "timeout_ms must be a positive integer up to 300000",
  entryNotFound: VaultError.renderEntryNotFound().message,
  inFlight: VaultError.renderInFlight().message,
  slotRefused: VaultError.renderSlotRefused().message,
  valueUnsupported: VaultError.renderValueUnsupported().message,
  failed: VaultError.renderFailed().message,
  hostNotAllowed: "Host not in secret allowlist",
  commandNotAllowed: "Command not in secret allowlist: ssh",
  belowFloor: VaultError.sshClientBelowFloor("8.3", "8.4", "render").message,
  unreadable: VaultError.sshClientBelowFloor(null, "8.4", "render").message,
  useFailed: "the use failed unexpectedly",
  injectionFailed: "the injection context failed unexpectedly",
  auditFailed: "the audit write failed unexpectedly",
};

let tempDir: string;
let engine: VaultEngine;
let keyId: string;
let ids: Record<string, string>;
let values: Record<string, string>;

interface EngineInternals {
  secretManager: SecretManager;
  store: SqliteStore;
  sftpRender: SftpRenderSeam;
  renderHolds: Set<string>;
  renderSlotLimiter: RateLimiter;
  loadInjectionPolicy: (s: unknown, secretId: string) => InjectionPolicy;
}

function internals(): EngineInternals {
  return engine as unknown as EngineInternals;
}

function unparsed(value: unknown): UseSecretAction {
  return value as UseSecretAction;
}

function render(fields: Record<string, unknown> = {}): UseSecretAction {
  return unparsed({ type: "sftp", operation: "render", entry: "env", ...fields });
}

function agent(id: string, extra: Partial<CallerContext> = {}): CallerContext {
  return { principal_type: "agent", principal_id: id, interface: "rest", ...extra };
}

const ALICE = agent("alice");

function draw(): string {
  return randomBytes(18).toString("hex");
}

function bytes(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "utf8"));
}

/** A word of `text` that the render's redaction list would hold: letters alone, three or more. */
function word(text: string): string {
  const words = text.split(/[^A-Za-z]+/).filter((w) => w.length >= 3);
  return words[randomInt(words.length)] as string;
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

function allZero(array: Uint8Array): boolean {
  return array.every((byte) => byte === 0);
}

async function makeSecret(handle: string, value: string): Promise<string> {
  const name = handle.slice(handle.lastIndexOf("/") + 1);
  const rest = handle.slice("secret://".length);
  const project = rest.includes("/") ? rest.slice(0, rest.indexOf("/")) : undefined;
  await engine.createSecret({ name, project, type: "api_key", value: bytes(value) });
  return engine.resolveSecretId(handle);
}

function grant(secretId: string, principalId: string, permissions: ("use" | "read")[]): void {
  engine.grantPolicy(
    { secretId, principalType: PrincipalType.AGENT, principalId, permissions },
    "test",
  );
}

/** Each slot approves each of `entries` on the key `of`, beside what `extra` sets. */
async function approve(
  entries: RenderEntry[],
  of: string = keyId,
  handles: string[] = SLOTS,
  extra: InjectionPolicyInput = {},
): Promise<void> {
  for (const handle of handles) {
    await engine.setInjectionPolicy(handle, {
      ...extra,
      render: { entries: [], approvals: entries.map((entry) => approval(of, entry)) },
    });
  }
}

async function keyEntries(entries: RenderEntry[]): Promise<void> {
  await engine.setInjectionPolicy(KEY, keyPolicy(entries));
  await approve(entries);
}

function useRows(secretId?: string) {
  return engine
    .queryAudit({ eventType: AuditEventType.SECRET_USE, ...(secretId ? { secretId } : {}) })
    .reverse();
}

function details(secretId?: string): (Record<string, unknown> | null)[] {
  return useRows(secretId).map((row) => row.detail);
}

/** The key's row and each slot's, in the order the call wrote them, with `success`. */
function callRows(): { key: unknown; slots: unknown[] } {
  const shape = (row: ReturnType<typeof useRows>[number]) => ({
    detail: row.detail,
    success: row.success,
  });
  return {
    key: useRows(keyId).map(shape),
    slots: SLOTS.map((handle) => useRows(ids[handle]).map(shape)),
  };
}

function k(extra: Record<string, unknown>): Record<string, unknown> {
  return { ...R, slots: SLOTS, written: "no", ...ISO, ...REST, ...extra };
}

function s(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { ...S, ...ISO, ...REST, ...extra };
}

/** The four rows of a failed call: `K` with `key`, every `S` failed, `error` on the slot named in `slotErrors`. */
function expectFailedRows(key: Record<string, unknown>, slotErrors: Record<string, string> = {}) {
  expect(callRows()).toStrictEqual({
    key: [{ detail: k(key), success: false }],
    slots: SLOTS.map((handle) => [
      {
        detail: s(slotErrors[handle] === undefined ? {} : { error: slotErrors[handle] }),
        success: false,
      },
    ]),
  });
}

/**
 * Replaces the live manager's decrypt: `hook` sees each handle and the real decrypt, and answers
 * the array the engine gets; every array the engine got is kept to see its wipe.
 */
function onDecrypt(
  hook: (handle: string, decrypt: () => Promise<Uint8Array>) => Promise<Uint8Array>,
): { handles: string[]; retained: Uint8Array[] } {
  const manager = internals().secretManager;
  const decrypt = manager.getSecretValue.bind(manager);
  const seen = { handles: [] as string[], retained: [] as Uint8Array[] };
  manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
    seen.handles.push(args[0]);
    const value = await hook(args[0], () => decrypt(...args));
    seen.retained.push(value);
    return value;
  };
  return seen;
}

/** The value the engine gets for `handle` is `crafted`; the real one is wiped. */
function craft(handle: string, crafted: () => Uint8Array) {
  return onDecrypt(async (seen, decrypt) => {
    const real = await decrypt();
    if (seen !== handle) return real;
    real.fill(0);
    return crafted();
  });
}

/** From now on, the `nth` audit insert throws; every other one is written. */
function failAuditInsert(nth: number): void {
  const live = internals().store;
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

/** A copy of the content `run` was handed, taken inside `run`: the engine zeroes it after. */
function copyContent(into: Buffer[]) {
  return (plan: RenderPlan): undefined => {
    into.push(Buffer.from(plan.content));
    return undefined;
  };
}

/** Every string a call hands back or writes: results, messages and each row's detail. */
function expectNoValue(texts: string[]): void {
  const rows = JSON.stringify(details());
  for (const [handle, value] of Object.entries(values)) {
    expectAbsent(rows, value, `the rows, for ${handle}`);
    for (const text of texts) expectAbsent(text, value, `an answer, for ${handle}`);
  }
}

// The engine-building hook ran past core's 30 s on the loaded windows-latest Node 24 leg (ci.yml
// run 45594869586).
const HOOK_TIMEOUT_MS = 120_000;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-render-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  values = { [KEY]: draw(), [BOT]: draw(), [API]: draw(), [DB]: draw() };
  keyId = await makeSecret(KEY, values[KEY] as string);
  ids = { [KEY]: keyId };
  for (const handle of SLOTS) ids[handle] = await makeSecret(handle, values[handle] as string);
  await keyEntries([ENTRY]);
  registerAgents(engine, "alice", "bob");
  for (const id of Object.values(ids)) grant(id, "alice", ["use"]);
}, HOOK_TIMEOUT_MS);

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}, HOOK_TIMEOUT_MS);

describe("the engine's render seam", () => {
  it("holds the injector's run and the render's version read", async () => {
    const seam = internals().sftpRender;
    expect(Object.keys(seam).sort()).toStrictEqual(["refuseOldClient", "run"]);
    expect(seam.run).toBe(runRender);
    const err = await expectVaultError(
      () => seam.refuseOldClient(join(tempDir, "no-such-ssh"), []),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(TEXT.unreadable);
  });
});

describe("useSecret — a render's door and the handle's own ladder", () => {
  it("a render with a host is refused at the door without a row", async () => {
    const resolve = vi.spyOn(internals().secretManager, "resolveHandle");
    const before = nonReadAuditCount(engine);

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render({ host: "h1.example" }), ALICE),
      ErrorCode.INVALID_INPUT,
    );

    expect(err.message).toBe(TEXT.forbidden);
    expect(resolve).not.toHaveBeenCalled();
    expect(nonReadAuditCount(engine)).toBe(before);
  });

  itSsh("operation, entry, timeout_ms and host are read once, by the door's copy", async () => {
    installRenderSeam(engine);
    const reads: Record<string, number> = {};
    const getter = (key: string, value: unknown) => ({
      enumerable: true,
      get: () => {
        reads[key] = (reads[key] ?? 0) + 1;
        return value;
      },
    });
    const action = Object.defineProperties(
      { type: "sftp" },
      {
        operation: getter("operation", "render"),
        entry: getter("entry", "env"),
        timeout_ms: getter("timeout_ms", undefined),
        host: getter("host", undefined),
      },
    );

    await expect(engine.useSecret(KEY, unparsed(action), ALICE)).resolves.toStrictEqual(RESULT);

    expect(reads).toStrictEqual({ operation: 1, entry: 1, timeout_ms: 1, host: 1 });
  });

  it.each([
    {
      what: "a revoked key",
      arrange: () => engine.revokeSecret(KEY),
      as: ALICE,
      action: render(),
      code: ErrorCode.SECRET_REVOKED,
      row: { handle: KEY, context: "sftp", error: ErrorCode.SECRET_REVOKED, ...REST },
    },
    {
      what: "a caller without the grant",
      arrange: () => Promise.resolve(),
      as: agent("bob"),
      action: render(),
      code: ErrorCode.SECRET_NOT_FOUND,
      row: {
        handle: KEY,
        context: "sftp",
        required_permission: "use",
        error: ErrorCode.ACCESS_DENIED,
        ...REST,
      },
    },
    {
      what: "a timeout_ms over the bound beside an unknown entry",
      arrange: () => Promise.resolve(),
      as: ALICE,
      action: render({ entry: "nope", timeout_ms: 300_001 }),
      code: ErrorCode.INVALID_INPUT,
      row: { handle: KEY, context: "sftp", error: ErrorCode.INVALID_INPUT, ...REST },
    },
  ])(
    "the handle's own refusals answer first — $what",
    async ({ arrange, as, action, code, row }) => {
      const calls = installRenderSeam(engine);
      await arrange();
      const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

      const err = await expectVaultError(() => engine.useSecret(KEY, action, as), code);

      if (code === ErrorCode.INVALID_INPUT) expect(err.message).toBe(TEXT.timeout);
      expect(decrypt).not.toHaveBeenCalled();
      expect(calls).toHaveLength(0);
      expect(details(keyId)).toStrictEqual([row]);
    },
  );

  itSsh(
    "an action whose type answers otherwise on a later read is judged by its first answer everywhere, neither a render nor a bootstrap beside a stored block",
    async () => {
      storeInjectionPolicyBlob(
        engine,
        keyId,
        injectionPolicyInputSchema.parse({ ...keyPolicy([ENTRY]), ssh_bootstrap: BLOCK }),
      );
      const calls = installRenderSeam(engine);
      (engine as unknown as { sshBootstrap: SshBootstrapSeam }).sshBootstrap = {
        refuseVaultHost: () => undefined,
        refuseOldClient: () => Promise.resolve(),
        run: () => Promise.reject(VaultError.sshConnectFailed()),
      };
      const answers = (first: string[], then: string) => {
        let reads = 0;
        return { enumerable: true, get: () => first[reads++] ?? then };
      };
      const action = Object.defineProperties(
        { host: BOOT.host, user: BOOT.user, public_key: BOOT.public_key, entry: "env" },
        {
          type: answers(["http", "ssh", "sftp"], "ssh"),
          operation: answers(["bootstrap", "render"], "bootstrap"),
          timeout_ms: { enumerable: true, value: 300_001 },
        },
      );

      await expectVaultError(
        () => engine.useSecret(KEY, unparsed(action), ALICE),
        ErrorCode.RENDER_ONLY_KEY,
      );

      expect(calls).toHaveLength(0);
      expect(details(keyId)).toStrictEqual([
        { handle: KEY, context: "http", error: ErrorCode.RENDER_ONLY_KEY, ...REST },
      ]);
    },
  );
});

describe("useSecret — a render's entry, before the hold (step 2)", () => {
  function expectRefusedAlone(row: Record<string, unknown>): void {
    expect(useRows()).toHaveLength(1);
    expect(useRows(keyId).map((r) => ({ detail: r.detail, success: r.success }))).toStrictEqual([
      { detail: row, success: false },
    ]);
  }

  it("no entry of that name, also on a key without entries", async () => {
    const calls = installRenderSeam(engine);
    const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render({ entry: "nope" })),
      ErrorCode.RENDER_ENTRY_NOT_FOUND,
    );
    expect(err.message).toBe(TEXT.entryNotFound);
    expectRefusedAlone({ ...R0, entry: "nope", error: ErrorCode.RENDER_ENTRY_NOT_FOUND });

    const bare = await makeSecret("secret://bare-key", draw());
    await expectVaultError(
      () => engine.useSecret("secret://bare-key", render()),
      ErrorCode.RENDER_ENTRY_NOT_FOUND,
    );
    expect(details(bare)).toStrictEqual([
      { ...R0, entry: "env", error: ErrorCode.RENDER_ENTRY_NOT_FOUND },
    ]);
    expect(decrypt).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  itSsh("an entry that is no name past the door is rendered as the door read it", async () => {
    const calls = installRenderSeam(engine);
    let reads = 0;
    const action = Object.defineProperties(
      { type: "sftp", operation: "render" },
      {
        entry: {
          enumerable: true,
          get: () => {
            reads += 1;
            return reads === 1 ? "env" : "a b";
          },
        },
      },
    );

    await expect(engine.useSecret(KEY, unparsed(action), ALICE)).resolves.toStrictEqual(RESULT);

    expect(reads).toBe(1);
    expect(calls.map((call) => call.plan.entry.name)).toStrictEqual(["env"]);
  });

  it("an entry whose host the stored allowlist does not admit", async () => {
    const calls = installRenderSeam(engine);
    storeInjectionPolicyBlob(
      engine,
      keyId,
      injectionPolicyInputSchema.parse({ ...keyPolicy([ENTRY]), host_allowlist: ["h2.example"] }),
    );
    const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    expect(err.message).toBe(TEXT.hostNotAllowed);
    expect(decrypt).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expectRefusedAlone({ ...R, error: ErrorCode.HOST_NOT_ALLOWED, ...REST });
  });

  itSsh("ssh not on command_allowlist", async () => {
    const calls = installRenderSeam(engine);
    await engine.setInjectionPolicy(KEY, { ...keyPolicy([ENTRY]), command_allowlist: [] });
    const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
    expect(err.message).toBe(TEXT.commandNotAllowed);
    expect(decrypt).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expectRefusedAlone({ ...R, error: ErrorCode.COMMAND_NOT_ALLOWED, ...REST });
  });

  itSsh("a client below the floor", async () => {
    const seen: [string, readonly string[]][] = [];
    const calls = installRenderSeam(engine, undefined, {
      refuseOldClient: (sshPath, envAllowlist) => {
        seen.push([sshPath, envAllowlist]);
        return Promise.reject(VaultError.sshClientBelowFloor("8.3", "8.4", "render"));
      },
    });
    await engine.setInjectionPolicy(KEY, { ...keyPolicy([ENTRY]), env_allowlist: ["LANG"] });
    const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(TEXT.belowFloor);
    expect(seen).toStrictEqual([[SSH, ["LANG"]]]);
    expect(decrypt).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
    expectRefusedAlone({ ...R, error: ErrorCode.SSH_CLIENT_UNSUPPORTED, ...REST });
  });

  itSsh("the refusals keep their order", async () => {
    installRenderSeam(engine, undefined, {
      refuseOldClient: () => Promise.reject(VaultError.sshClientBelowFloor("8.3", "8.4", "render")),
    });
    const stored = (policy: InjectionPolicyInput): void =>
      storeInjectionPolicyBlob(engine, keyId, injectionPolicyInputSchema.parse(policy));
    const all = { ...keyPolicy([ENTRY]), host_allowlist: ["h2.example"], command_allowlist: [] };

    stored(all);
    await expectVaultError(
      () => engine.useSecret(KEY, render({ entry: "nope" })),
      ErrorCode.RENDER_ENTRY_NOT_FOUND,
    );
    await expectVaultError(() => engine.useSecret(KEY, render()), ErrorCode.HOST_NOT_ALLOWED);
    stored({ ...all, host_allowlist: ["h1.example"] });
    await expectVaultError(() => engine.useSecret(KEY, render()), ErrorCode.COMMAND_NOT_ALLOWED);
    stored({ ...all, host_allowlist: ["h1.example"], command_allowlist: ["ssh"] });
    await expectVaultError(() => engine.useSecret(KEY, render()), ErrorCode.SSH_CLIENT_UNSUPPORTED);

    expect(details(keyId)).toStrictEqual([
      { ...R0, entry: "nope", error: ErrorCode.RENDER_ENTRY_NOT_FOUND },
      { ...R, error: ErrorCode.HOST_NOT_ALLOWED },
      { ...R, error: ErrorCode.COMMAND_NOT_ALLOWED },
      { ...R, error: ErrorCode.SSH_CLIENT_UNSUPPORTED },
    ]);
  });

  itSsh("a raw throw of the version read is the net's one row", async () => {
    const calls = installRenderSeam(engine, undefined, {
      refuseOldClient: () => Promise.reject(new Error("the version read broke")),
    });

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.INTERNAL_ERROR,
    );
    expect(err.message).toBe(TEXT.useFailed);
    expect(calls).toHaveLength(0);
    expectRefusedAlone({ handle: KEY, context: "sftp", error: ErrorCode.INTERNAL_ERROR, ...REST });
  });

  it.each([
    {
      what: "a template",
      entry: { ...ENTRY, template: "TOKEN={{secret://bot-token" },
      text: "Vault corrupted: a render template does not parse",
    },
    {
      what: "a host key line",
      entry: { ...ENTRY, host_keys: ["ssh-ed25519 x"] },
      text: "Vault corrupted: a render host key line does not parse",
    },
    {
      what: "a path",
      entry: { ...ENTRY, path: "/srv/app/../.env" },
      text: "Vault corrupted: a render path is not in normal form",
    },
  ])(
    "$what the stored schema would refuse is corruption, before any decrypt and without a row",
    async ({ entry, text }) => {
      const calls = installRenderSeam(engine);
      const load = internals().loadInjectionPolicy.bind(engine);
      vi.spyOn(internals(), "loadInjectionPolicy").mockImplementation((state, id) => {
        const policy = load(state, id);
        return id === keyId ? { ...policy, render: { entries: [entry], approvals: [] } } : policy;
      });
      const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");
      const before = nonReadAuditCount(engine);

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render(), ALICE),
        ErrorCode.VAULT_CORRUPTED,
      );

      expect(err.message).toBe(text);
      expect(nonReadAuditCount(engine)).toBe(before);
      expect(decrypt).not.toHaveBeenCalled();
      expect(calls).toHaveLength(0);
    },
  );
});

describe("useSecret — one render per host, port and path (step 3)", () => {
  const ENTRY_TWO: RenderEntry = { ...ENTRY, name: "env-two" };
  const KEY_TWO = "secret://deploy-key-2";

  /** A render of `entry` whose `run` waits until `release`; `entered` when it is in `run`. */
  function waitingRun(name: string) {
    const gate = deferred<undefined>();
    const entered = deferred<undefined>();
    const calls = installRenderSeam(engine, async (plan) => {
      if (plan.entry.name !== name) return undefined;
      entered.resolve(undefined);
      await gate.promise;
      return undefined;
    });
    return { calls, entered: entered.promise, release: () => gate.resolve(undefined) };
  }

  itSsh(
    "a second render to one host, port and path is refused in flight, whatever the key and the entry",
    async () => {
      const keyTwo = await makeSecret(KEY_TWO, draw());
      grant(keyTwo, "alice", ["use"]);
      await engine.setInjectionPolicy(KEY_TWO, keyPolicy([ENTRY_TWO]));
      for (const handle of SLOTS) {
        await engine.setInjectionPolicy(handle, {
          render: { entries: [], approvals: [approval(keyId, ENTRY), approval(keyTwo, ENTRY_TWO)] },
        });
      }
      const { calls, entered, release } = waitingRun("env");
      const first = quiet(engine.useSecret(KEY, render(), ALICE));
      await entered;
      const resolve = vi.spyOn(internals().secretManager, "resolveHandle");
      const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

      const err = await expectVaultError(
        () => engine.useSecret(KEY_TWO, render({ entry: "env-two" }), ALICE),
        ErrorCode.RENDER_IN_FLIGHT,
      );
      expect(err.message).toBe(TEXT.inFlight);
      expect(resolve.mock.calls).toStrictEqual([[KEY_TWO]]);
      expect(decrypt).not.toHaveBeenCalled();
      expect(details(keyTwo)).toStrictEqual([
        { ...R, entry: "env-two", error: ErrorCode.RENDER_IN_FLIGHT, ...REST },
      ]);

      release();
      await expect(first).resolves.toStrictEqual(RESULT);
      await expect(
        engine.useSecret(KEY_TWO, render({ entry: "env-two" }), ALICE),
      ).resolves.toStrictEqual(RESULT);
      expect(calls.map((call) => call.plan.entry.name)).toStrictEqual(["env", "env-two"]);

      const two = { entry: "env-two", key: KEY_TWO };
      expect(details(keyId)).toStrictEqual([k({ written: "yes" })]);
      expect(details(keyTwo)).toStrictEqual([
        { ...R, entry: "env-two", error: ErrorCode.RENDER_IN_FLIGHT, ...REST },
        k({ written: "yes", entry: "env-two" }),
      ]);
      for (const handle of SLOTS) {
        expect(useRows(ids[handle]).map((row) => [row.detail, row.success])).toStrictEqual([
          [s(), true],
          [s(two), true],
        ]);
      }
    },
  );

  itSsh("another port or another path is another target", async () => {
    const port: RenderEntry = { ...ENTRY, name: "port", port: 2222 };
    const path: RenderEntry = { ...ENTRY, name: "path", path: "/srv/app/.env2" };
    await keyEntries([ENTRY, port, path]);
    const { calls, entered, release } = waitingRun("env");
    const first = quiet(engine.useSecret(KEY, render(), ALICE));
    await entered;

    await expect(engine.useSecret(KEY, render({ entry: "port" }), ALICE)).resolves.toStrictEqual(
      RESULT,
    );
    await expect(engine.useSecret(KEY, render({ entry: "path" }), ALICE)).resolves.toStrictEqual(
      RESULT,
    );
    release();
    await expect(first).resolves.toStrictEqual(RESULT);
    expect(calls).toHaveLength(3);
  });

  itSsh("the host's case makes no second target", async () => {
    const upper: RenderEntry = { ...ENTRY, name: "upper", host: "H1.EXAMPLE" };
    await keyEntries([ENTRY, upper]);
    const { entered, release } = waitingRun("env");
    const first = quiet(engine.useSecret(KEY, render(), ALICE));
    await entered;

    await expectVaultError(
      () => engine.useSecret(KEY, render({ entry: "upper" }), ALICE),
      ErrorCode.RENDER_IN_FLIGHT,
    );
    release();
    await expect(first).resolves.toStrictEqual(RESULT);
  });

  itSsh.each([
    {
      what: "a refused slot",
      code: ErrorCode.RENDER_SLOT_REFUSED,
      arrange: async () => {
        installRenderSeam(engine);
        await approve([], keyId, [API]);
        return () => approve([ENTRY], keyId, [API]);
      },
    },
    {
      what: "a refused value",
      code: ErrorCode.RENDER_VALUE_UNSUPPORTED,
      arrange: () => {
        installRenderSeam(engine);
        const manager = internals().secretManager;
        const real = manager.getSecretValue;
        craft(API, () => bytes(`${draw()}!`));
        return Promise.resolve(() => {
          manager.getSecretValue = real;
        });
      },
    },
    {
      what: "a failed write",
      code: ErrorCode.RENDER_FAILED,
      arrange: () => {
        installRenderSeam(engine, () => ({
          kind: "ran",
          outcome: { written: "no", reason: "connect" },
          spawn: ISO,
        }));
        return Promise.resolve(() => installRenderSeam(engine));
      },
    },
    {
      what: "run throwing",
      code: ErrorCode.INTERNAL_ERROR,
      arrange: () => {
        installRenderSeam(engine, () => {
          throw new Error("run broke");
        });
        return Promise.resolve(() => installRenderSeam(engine));
      },
    },
    {
      what: "a seal",
      code: ErrorCode.VAULT_LOCKED,
      arrange: () => {
        installRenderSeam(engine, async () => {
          await engine.lock();
          return undefined;
        });
        return Promise.resolve(async () => {
          await engine.unlock("password");
          installRenderSeam(engine);
        });
      },
    },
  ])("the hold is given up on every way out — $what", async ({ code, arrange }) => {
    const restore = await arrange();

    await expectVaultError(() => engine.useSecret(KEY, render(), ALICE), code);

    expect(internals().renderHolds.size).toBe(0);
    await restore();
    await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);
  });
});

describe("useSecret — a render's decrypts (step 5)", () => {
  itSsh(
    "decrypts the key, then each distinct slot once, and only after every slot was judged",
    async () => {
      installRenderSeam(engine);
      const resolve = vi.spyOn(internals().secretManager, "resolveHandle");
      const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

      await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);

      expect(decrypt.mock.calls.map((call) => call[0])).toStrictEqual([KEY, BOT, API, DB]);
      expect(resolve.mock.calls.map((call) => call[0])).toStrictEqual([KEY, BOT, API, DB]);
      const lastJudged = Math.max(...resolve.mock.invocationCallOrder);
      expect(Math.min(...decrypt.mock.invocationCallOrder)).toBeGreaterThan(lastJudged);

      decrypt.mockClear();
      await approve([], keyId, [DB]);
      await expectVaultError(
        () => engine.useSecret(KEY, render(), ALICE),
        ErrorCode.RENDER_SLOT_REFUSED,
      );
      expect(decrypt).not.toHaveBeenCalled();
    },
  );

  itSsh(
    "the same handle in two slots is judged, charged, decrypted and recorded once",
    async () => {
      const twice: RenderEntry = {
        ...ENTRY,
        name: "twice",
        template: "A={{secret://bot-token}}\nB={{secret://bot-token}}\n",
      };
      await keyEntries([ENTRY, twice]);
      const content: Buffer[] = [];
      installRenderSeam(engine, copyContent(content));
      const resolve = vi.spyOn(internals().secretManager, "resolveHandle");
      const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");
      const charge = vi.spyOn(internals().renderSlotLimiter, "checkSecret");

      await expect(engine.useSecret(KEY, render({ entry: "twice" }), ALICE)).resolves.toStrictEqual(
        RESULT,
      );

      expect(resolve.mock.calls.map((call) => call[0])).toStrictEqual([KEY, BOT]);
      expect(decrypt.mock.calls.map((call) => call[0])).toStrictEqual([KEY, BOT]);
      expect(charge).toHaveBeenCalledTimes(1);
      expect(details(ids[BOT])).toStrictEqual([s({ entry: "twice" })]);
      expect(details(keyId)).toStrictEqual([k({ written: "yes", entry: "twice", slots: [BOT] })]);
      const expected = Buffer.from(`A=${values[BOT] as string}\nB=${values[BOT] as string}\n`);
      expect((content[0] as Buffer).equals(expected)).toBe(true);
    },
  );

  itSsh("a key that came to name another secret is refused", async () => {
    const calls = installRenderSeam(engine);
    const other = draw();
    const seen = onDecrypt(async (handle, decrypt) => {
      if (handle === KEY) {
        await engine.revokeSecret(KEY);
        await engine.createSecret({ name: "deploy-key", type: "api_key", value: bytes(other) });
      }
      return decrypt();
    });

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.SECRET_REVOKED,
    );

    expectAbsent(err.message, other);
    expectAbsent(JSON.stringify(details()), other);
    expect(err.message).toBe("Secret revoked");
    expect(calls).toHaveLength(0);
    expect(seen.handles).toStrictEqual([KEY]);
    expect(seen.retained.every(allZero)).toBe(true);
    expectFailedRows({ error: ErrorCode.SECRET_REVOKED });
  });

  itSsh(
    "a slot secret created again under its name between judgement and decrypt is refused",
    async () => {
      const calls = installRenderSeam(engine);
      const other = draw();
      const seen = onDecrypt(async (handle, decrypt) => {
        if (handle === API) {
          await engine.revokeSecret(API);
          await engine.createSecret({ name: "api-key", type: "api_key", value: bytes(other) });
        }
        return decrypt();
      });

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render(), ALICE),
        ErrorCode.RENDER_SLOT_REFUSED,
      );

      expectAbsent(err.message, other);
      expectAbsent(JSON.stringify(details()), other);
      expect(err.message).toBe(TEXT.slotRefused);
      expect(calls).toHaveLength(0);
      expect(seen.handles).toStrictEqual([KEY, BOT, API]);
      expect(seen.retained.every(allZero)).toBe(true);
      expectFailedRows(
        { error: ErrorCode.RENDER_SLOT_REFUSED },
        { [API]: ErrorCode.SECRET_REVOKED },
      );
    },
  );

  itSsh.each<{ what: string; handle: string; code: ErrorCode; slotErrors: Record<string, string> }>(
    [
      { what: "the key", handle: KEY, code: ErrorCode.SECRET_REVOKED, slotErrors: {} },
      {
        what: "a slot",
        handle: API,
        code: ErrorCode.RENDER_SLOT_REFUSED,
        slotErrors: { [API]: ErrorCode.SECRET_REVOKED },
      },
    ],
  )(
    "$what that came to name a pending secret is refused as revoked, not with that secret's code",
    async ({ handle, code, slotErrors }) => {
      const calls = installRenderSeam(engine);
      onDecrypt(async (seen, decrypt) => {
        if (seen === handle) {
          await engine.revokeSecret(handle);
          await engine.createSecret({ name: handle.slice("secret://".length), type: "api_key" });
        }
        return decrypt();
      });

      await expectVaultError(() => engine.useSecret(KEY, render(), ALICE), code);

      expect(calls).toHaveLength(0);
      expectFailedRows(
        { error: handle === KEY ? ErrorCode.SECRET_REVOKED : ErrorCode.RENDER_SLOT_REFUSED },
        slotErrors,
      );
    },
  );

  itSsh("a slot that expired meanwhile", async () => {
    const calls = installRenderSeam(engine);
    const terminate = vi.spyOn(registryOf(engine), "terminate");
    onDecrypt(async (handle, decrypt) => {
      if (handle === DB) internals().store.updateSecret(ids[DB] as string, { expires_at: 1 });
      return decrypt();
    });

    await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.RENDER_SLOT_REFUSED,
    );

    expect(calls).toHaveLength(0);
    expectFailedRows({ error: ErrorCode.RENDER_SLOT_REFUSED }, { [DB]: ErrorCode.SECRET_EXPIRED });
    expect(
      engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE, secretId: ids[DB] }),
    ).toHaveLength(1);
    expect(terminate).toHaveBeenCalledWith(ids[DB], "secret_unusable", expect.anything());
  });

  itSsh("the key's refused decrypt ends its live child as the use path's does", async () => {
    installRenderSeam(engine);
    const terminate = vi.spyOn(registryOf(engine), "terminate");
    onDecrypt(async (handle, decrypt) => {
      if (handle === KEY) internals().store.updateSecret(keyId, { expires_at: 1 });
      return decrypt();
    });

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.SECRET_EXPIRED,
    );

    expectNoValue([err.message]);
    expect(err.message).toBe(`Secret expired: ${KEY}`);
    for (const slot of SLOTS) expect(err.message).not.toContain(slot.slice("secret://".length));
    expectFailedRows({ error: ErrorCode.SECRET_EXPIRED });
    expect(terminate).toHaveBeenCalledWith(keyId, "secret_unusable", expect.anything());
  });
});

describe("useSecret — a render's values (step 5, § 6.6)", () => {
  const filled = (length: number): Uint8Array => {
    let text = "";
    while (text.length < length) text += draw();
    return bytes(text.slice(0, length));
  };

  itSsh.each([
    { what: "empty", value: () => new Uint8Array(0) },
    { what: "a NUL", value: () => bytes(`${draw()}\u0000${draw()}`) },
    {
      what: "the bytes 0xc3 0x28",
      value: () => new Uint8Array([...Buffer.from(draw()), 0xc3, 0x28]),
    },
    { what: "65 537 bytes", value: () => filled(65_537) },
    { what: "a line feed", value: () => bytes(`${draw()}\n${draw()}`) },
    { what: "${OTHER}", value: () => bytes(`${draw()}\${OTHER}`) },
    { what: "$(id)", value: () => bytes(`${draw()}$(id)`) },
    { what: "a double quote", value: () => bytes(`${draw()}"${draw()}`) },
    { what: "U+2028", value: () => bytes(`${draw()}\u2028${draw()}`) },
    { what: "a blank", value: () => bytes(`${draw()} ${draw()}`) },
    { what: "an exclamation mark", value: () => bytes(`${draw()}!`) },
  ])(
    "a value a mixed template cannot hold is refused after the decrypts, before the connection — $what",
    async ({ value }) => {
      const calls = installRenderSeam(engine);
      const seen = craft(API, value);

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render(), ALICE),
        ErrorCode.RENDER_VALUE_UNSUPPORTED,
      );

      expectNoValue([err.message]);
      expect(err.message).toBe(TEXT.valueUnsupported);
      expect(calls).toHaveLength(0);
      expect(seen.handles).toStrictEqual([KEY, BOT, API, DB]);
      expect(seen.retained.every(allZero)).toBe(true);
      expectFailedRows(
        { error: ErrorCode.RENDER_VALUE_UNSUPPORTED },
        { [API]: ErrorCode.RENDER_VALUE_UNSUPPORTED },
      );
    },
  );

  describe("a one-slot template", () => {
    beforeEach(async () => {
      await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, ENTRY_ONE]));
      await approve([ENTRY, ENTRY_ONE], keyId, [BOT]);
    });

    itSsh.each([
      { what: "the line feed", value: () => `${draw()}\n${draw()}\n` },
      { what: "the quote", value: () => `"${draw()}"` },
      { what: "the blank", value: () => `${draw()} ${draw()}` },
    ])("takes $what", async ({ value }) => {
      const text = value();
      const content: Buffer[] = [];
      installRenderSeam(engine, copyContent(content));
      craft(BOT, () => bytes(text));

      await expect(engine.useSecret(KEY, render({ entry: "pem" }), ALICE)).resolves.toStrictEqual(
        RESULT,
      );
      expect((content[0] as Buffer).equals(Buffer.from(text))).toBe(true);
    });

    itSsh.each([
      { what: "the empty", value: () => new Uint8Array(0) },
      { what: "the NUL", value: () => bytes(`${draw()}\u0000`) },
      { what: "the invalid", value: () => new Uint8Array([0xc3, 0x28]) },
      { what: "the oversized", value: () => filled(65_537) },
    ])("and still refuses $what", async ({ value }) => {
      const calls = installRenderSeam(engine);
      craft(BOT, value);

      await expectVaultError(
        () => engine.useSecret(KEY, render({ entry: "pem" }), ALICE),
        ErrorCode.RENDER_VALUE_UNSUPPORTED,
      );
      expect(calls).toHaveLength(0);
      expect(details(ids[BOT])).toStrictEqual([
        {
          ...s({ entry: "pem", remote_path: "/srv/app/key.pem" }),
          error: ErrorCode.RENDER_VALUE_UNSUPPORTED,
        },
      ]);
    });
  });

  itSsh("65 536 bytes and every character of the class are served", async () => {
    const big = filled(65_536);
    const every = `${MIXED_CLASS}${draw()}`;
    const content: Buffer[] = [];
    installRenderSeam(engine, copyContent(content));
    onDecrypt(async (handle, decrypt) => {
      const real = await decrypt();
      if (handle === BOT) return new Uint8Array(big);
      if (handle === API) return bytes(every);
      return real;
    });

    await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);

    const expected = Buffer.concat([
      Buffer.from("TOKEN="),
      Buffer.from(big),
      Buffer.from(`\nAPI=${every}\nDB=${values[DB] as string}\n`),
    ]);
    expect((content[0] as Buffer).equals(expected)).toBe(true);
  });
});

describe("useSecret — what run is handed (steps 5 and 6)", () => {
  itSsh(
    "run gets the entry, the resolved ssh, the key's text, the content and the list",
    async () => {
      const crlf: RenderEntry = {
        ...ENTRY,
        name: "crlf",
        template: ENTRY.template.replaceAll("\n", "\r\n"),
      };
      await keyEntries([ENTRY, crlf]);
      const content: Buffer[] = [];
      const calls = installRenderSeam(engine, copyContent(content));

      await expect(engine.useSecret(KEY, render({ entry: "crlf" }), ALICE)).resolves.toStrictEqual(
        RESULT,
      );

      const { plan } = calls[0] as { plan: RenderPlan };
      expect(plan.entry).toStrictEqual(crlf);
      expect(plan.sshPath).toBe(SSH);
      expect(plan.keyPem === values[KEY]).toBe(true);
      const [bot, api, db] = [values[BOT], values[API], values[DB]] as string[];
      const expected = Buffer.from(`TOKEN=${bot}\r\nAPI=${api}\r\nDB=${db}\r\n`);
      expect((content[0] as Buffer).equals(expected)).toBe(true);
      expect(JSON.stringify(plan.redact) === JSON.stringify([values[KEY], bot, api, db])).toBe(
        true,
      );
      expect(plan.timeoutMs).toBe(30_000);
      expect(plan.policy).toStrictEqual(injectionPolicyInputSchema.parse(keyPolicy([ENTRY, crlf])));

      const short = randomBytes(1).toString("hex");
      craft(API, () => bytes(short));
      await expect(
        engine.useSecret(KEY, render({ timeout_ms: 5000 }), ALICE),
      ).resolves.toStrictEqual(RESULT);
      const second = (calls[1] as { plan: RenderPlan }).plan;
      expect(JSON.stringify(second.redact) === JSON.stringify([values[KEY], bot, db])).toBe(true);
      expect(second.timeoutMs).toBe(5000);
    },
  );

  itSsh("fs_isolation and strict_tree_exit are on where a slot's policy sets them", async () => {
    await approve([ENTRY], keyId, [DB], { fs_isolation: true });
    await approve([ENTRY], keyId, [API], { strict_tree_exit: true });
    const calls = installRenderSeam(engine, (plan) => ({
      kind: "ran",
      outcome: { written: "yes" },
      spawn: {
        network_isolation: plan.policy.network_isolation,
        fs_isolation: plan.policy.fs_isolation,
      },
    }));

    await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);

    const { plan } = calls[0] as { plan: RenderPlan };
    expect(plan.policy.fs_isolation).toBe(true);
    expect(plan.policy.strict_tree_exit).toBe(true);
    expect(details(keyId)).toStrictEqual([k({ written: "yes", fs_isolation: true })]);
    expect(details(ids[BOT])).toStrictEqual([s({ fs_isolation: true })]);
  });

  itSsh("the key's own fs_isolation and strict_tree_exit are handed on", async () => {
    await engine.setInjectionPolicy(KEY, {
      ...keyPolicy([ENTRY]),
      fs_isolation: true,
      strict_tree_exit: true,
    });
    const calls = installRenderSeam(engine);

    await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);

    const { plan } = calls[0] as { plan: RenderPlan };
    expect(plan.policy.fs_isolation).toBe(true);
    expect(plan.policy.strict_tree_exit).toBe(true);
  });

  itSsh.each([
    { what: "written", answer: () => undefined, code: undefined },
    {
      what: "a failed write",
      answer: (): RenderRun => ({
        kind: "ran",
        outcome: { written: "no", reason: "write" },
        spawn: ISO,
      }),
      code: ErrorCode.RENDER_FAILED,
    },
    {
      what: "a throw",
      answer: () => {
        throw new Error("run broke");
      },
      code: ErrorCode.INTERNAL_ERROR,
    },
  ])(
    "every array and the content are zero when the call has ended — $what",
    async ({ answer, code }) => {
      const calls = installRenderSeam(engine, answer);
      const retained = retainDecryptedValues(engine);

      if (code === undefined) await engine.useSecret(KEY, render(), ALICE);
      else await expectVaultError(() => engine.useSecret(KEY, render(), ALICE), code);

      expect(retained).toHaveLength(4);
      expect(retained.every(allZero)).toBe(true);
      expect(allZero((calls[0] as { plan: RenderPlan }).plan.content)).toBe(true);
    },
  );

  itSsh("the content is one buffer of its own, of the pieces' and the values' length", async () => {
    const calls = installRenderSeam(engine);

    await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);

    const { content } = (calls[0] as { plan: RenderPlan }).plan;
    const pieces = "TOKEN=\nAPI=\nDB=\n".length;
    const length =
      pieces + SLOTS.reduce((sum, handle) => sum + (values[handle] as string).length, 0);
    expect(content.byteLength).toBe(length);
    expect(content.byteOffset).toBe(0);
    expect(content.buffer.byteLength).toBe(length);
  });
});

describe("useSecret — a render's rows and answer (step 7)", () => {
  itSsh(
    "a written render leaves one row on the key and one on each slot, in one transaction",
    async () => {
      installRenderSeam(engine);

      const result = await engine.useSecret(KEY, render(), ALICE);

      expectNoValue([JSON.stringify(result)]);
      expect(result).toStrictEqual(RESULT);
      const rows = useRows();
      expect(rows).toHaveLength(4);
      expect(
        rows.map((row) => ({
          secret: row.secret_id,
          principal: row.principal_id,
          success: row.success,
          detail: row.detail,
        })),
      ).toStrictEqual([
        { secret: keyId, principal: "alice", success: true, detail: k({ written: "yes" }) },
        ...SLOTS.map((handle) => ({
          secret: ids[handle],
          principal: "alice",
          success: true,
          detail: s(),
        })),
      ]);
      const rowIds = rows.map((row) => row.id);
      expect(rowIds).toStrictEqual([0, 1, 2, 3].map((i) => (rowIds[0] as number) + i));
      expect(engine.verifyAuditChain().valid).toBe(true);
    },
  );

  itSsh("a template without a slot is served, the key's row alone", async () => {
    const plain: RenderEntry = { ...ENTRY, name: "plain", template: "MODE=production\n" };
    await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY, plain]));
    const content: Buffer[] = [];
    installRenderSeam(engine, copyContent(content));
    const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

    await expect(engine.useSecret(KEY, render({ entry: "plain" }), ALICE)).resolves.toStrictEqual(
      RESULT,
    );

    expect(decrypt.mock.calls.map((call) => call[0])).toStrictEqual([KEY]);
    expect((content[0] as Buffer).equals(Buffer.from("MODE=production\n"))).toBe(true);
    expect(details()).toStrictEqual([k({ written: "yes", entry: "plain", slots: [] })]);
  });

  itSsh("the key's row takes the seam's six spawn fields by name", async () => {
    const six = {
      isolation_mechanism: "unshare",
      fs_isolation_mechanism: "landlock",
      sanitized: true,
      descendant_sweep: { killed: 1, failed: false },
      tree_kill: "job",
      strict_tree_exit: true,
    };
    installRenderSeam(
      engine,
      () =>
        ({
          kind: "ran",
          outcome: { written: "yes" },
          spawn: {
            network_isolation: true,
            fs_isolation: true,
            ...six,
            exit_code: 9,
            timed_out: true,
            truncated: true,
            written: "no",
            error: "NONE",
            reason: "connect",
            host: "elsewhere.example",
            slots: [],
            stdout: "a line of the host",
          },
        }) as unknown as RenderRun,
    );

    await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);

    expect(details(keyId)).toStrictEqual([
      k({ written: "yes", network_isolation: true, fs_isolation: true, ...six }),
    ]);
    for (const handle of SLOTS) {
      expect(details(ids[handle])).toStrictEqual([
        s({ network_isolation: true, fs_isolation: true }),
      ]);
    }
  });

  itSsh.each([
    { written: "no", reason: "connect" },
    { written: "no", reason: "host_key" },
    { written: "no", reason: "no_rename" },
    { written: "no", reason: "protocol" },
    { written: "no", reason: "open" },
    { written: "no", reason: "mode" },
    { written: "no", reason: "write" },
    { written: "unconfirmed", reason: "rename" },
    { written: "unconfirmed", reason: "timeout" },
    { written: "unconfirmed", reason: undefined },
    { written: "yes", reason: "rename" },
  ] as const)("each failure of the write — written $written, reason $reason", async (outcome) => {
    installRenderSeam(engine, () => ({
      kind: "ran",
      outcome: outcome.reason === undefined ? { written: outcome.written } : outcome,
      spawn: ISO,
    }));

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.RENDER_FAILED,
    );

    expect(err.message).toBe(TEXT.failed);
    expectFailedRows({
      written: outcome.written,
      error: ErrorCode.RENDER_FAILED,
      ...(outcome.reason === undefined ? {} : { reason: outcome.reason }),
    });
  });

  itSsh.each([
    {
      what: "with the child's flags",
      spawn: { network_isolation: false, fs_isolation: true },
      flags: { fs_isolation: true },
    },
    { what: "before a child", spawn: undefined, flags: {} },
  ])(
    "run answering not_spawned keeps its code and its text, two slots' values words of it — $what",
    async ({ spawn, flags }) => {
      const text = VaultError.fsIsolationUnavailable("no mechanism on this host").message;
      await engine.rotateSecret(BOT, bytes(word(text)));
      await engine.rotateSecret(API, bytes(word(text)));
      installRenderSeam(engine, (_plan, control) => {
        control.written = "no";
        return {
          kind: "not_spawned",
          error: new VaultError(ErrorCode.FS_ISOLATION_UNAVAILABLE, text),
          ...(spawn === undefined ? {} : { spawn }),
        };
      });

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render(), ALICE),
        ErrorCode.FS_ISOLATION_UNAVAILABLE,
      );

      expect(err.message).toBe(text);
      expect(callRows()).toStrictEqual({
        key: [
          { detail: k({ error: ErrorCode.FS_ISOLATION_UNAVAILABLE, ...flags }), success: false },
        ],
        slots: SLOTS.map(() => [{ detail: s(flags), success: false }]),
      });
    },
  );

  itSsh("run throwing a VaultError keeps its code, stripped of every value", async () => {
    installRenderSeam(engine, () => {
      throw new VaultError(ErrorCode.SSH_AGENT_FAILED, `agent down for ${values[DB] as string}`);
    });

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.SSH_AGENT_FAILED,
    );

    expectNoValue([err.message]);
    expect(err.message).toBe("agent down for [REDACTED]");
    expectFailedRows({ error: ErrorCode.SSH_AGENT_FAILED });
  });

  itSsh("run throwing raw", async () => {
    installRenderSeam(engine, () => {
      throw new Error(`raw ${values[BOT] as string}`);
    });

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.INTERNAL_ERROR,
    );

    expectNoValue([err.message]);
    expect(err.message).toBe(TEXT.injectionFailed);
    expectFailedRows({ error: ErrorCode.INTERNAL_ERROR });
  });

  itSsh.each([1, 2])("the rows' commit failing — its row %i", async (nth) => {
    installRenderSeam(engine, () => {
      failAuditInsert(nth);
      return undefined;
    });

    const err = await expectVaultError(
      () => engine.useSecret(KEY, render(), ALICE),
      ErrorCode.INTERNAL_ERROR,
    );

    expect(err.message).toBe(TEXT.auditFailed);
    expect(useRows()).toStrictEqual([]);
    expect(internals().renderHolds.size).toBe(0);
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  itSsh("no value is in an answer, a message or a row", async () => {
    const texts: string[] = [];
    const answers: (() => unknown)[] = [
      () => undefined,
      () => ({ kind: "ran", outcome: { written: "no", reason: "open" }, spawn: ISO }),
      () => ({ kind: "not_spawned", error: VaultError.sshAgentFailed("invalid private key") }),
      () => {
        throw new VaultError(ErrorCode.SSH_AGENT_FAILED, `${values[KEY] as string}`);
      },
      () => {
        throw new Error(`${values[BOT] as string} ${values[API] as string}`);
      },
    ];
    for (const answer of answers) {
      installRenderSeam(engine, answer);
      try {
        texts.push(JSON.stringify(await engine.useSecret(KEY, render(), ALICE)));
      } catch (err) {
        texts.push((err as Error).message, JSON.stringify((err as VaultError).details ?? null));
      }
    }
    const manager = internals().secretManager;
    const real = manager.getSecretValue;
    craft(DB, () => bytes(`${values[DB] as string} `));
    try {
      await engine.useSecret(KEY, render(), ALICE);
    } catch (err) {
      texts.push((err as Error).message);
    }
    manager.getSecretValue = real;

    expect(texts.length).toBeGreaterThanOrEqual(5);
    expectNoValue(texts);
  });

  itSsh.each([
    {
      what: "a failed write",
      text: TEXT.failed,
      code: ErrorCode.RENDER_FAILED,
      arrange: () => {
        installRenderSeam(engine, () => ({
          kind: "ran",
          outcome: { written: "no", reason: "connect" },
          spawn: ISO,
        }));
      },
    },
    {
      what: "a refused value",
      text: TEXT.valueUnsupported,
      code: ErrorCode.RENDER_VALUE_UNSUPPORTED,
      arrange: () => {
        installRenderSeam(engine);
        craft(API, () => bytes(`${draw()}!`));
      },
    },
    {
      what: "a slot refused at its decrypt",
      text: TEXT.slotRefused,
      code: ErrorCode.RENDER_SLOT_REFUSED,
      arrange: () => {
        installRenderSeam(engine);
        onDecrypt(async (handle, decrypt) => {
          if (handle === DB) {
            await engine.revokeSecret(DB);
            await engine.createSecret({ name: "db-pass", type: "api_key", value: bytes(draw()) });
          }
          return decrypt();
        });
      },
    },
  ])("a fixed text reads letter for letter — $what", async ({ text, code, arrange }) => {
    const stored = word(text);
    await engine.rotateSecret(BOT, bytes(stored));
    arrange();

    const err = await expectVaultError(() => engine.useSecret(KEY, render(), ALICE), code);

    expect(err.message).toBe(text);
  });

  itSsh(
    "a fixed text reads letter for letter — the injector's own run, which the key's text ends before a spawn",
    async () => {
      const refusal = await expectVaultError(
        () => EphemeralSshAgent.start(values[KEY] as string),
        ErrorCode.SSH_AGENT_FAILED,
      );
      const text = refusal.message;
      await engine.rotateSecret(BOT, bytes(word(text)));
      await engine.rotateSecret(API, bytes(word(text)));
      installRenderSeam(engine, undefined, { run: runRender });

      const err = await expectVaultError(
        () => engine.useSecret(KEY, render(), ALICE),
        ErrorCode.SSH_AGENT_FAILED,
      );

      expect(err.message).toBe(text);
      expectFailedRows({ error: ErrorCode.SSH_AGENT_FAILED });
    },
  );
});

describe("useSecret — an administrator's write under a running render", () => {
  itSsh.each([
    { what: "a slot revoked (secret delete)", write: () => engine.revokeSecret(API), revokes: 1 },
    { what: "the key revoked", write: () => engine.revokeSecret(KEY), revokes: 1 },
    {
      what: "the entry removed",
      write: () => engine.setInjectionPolicy(KEY, keyPolicy([])),
      revokes: 0,
    },
    { what: "the approval revoked", write: () => approve([], keyId, [DB]), revokes: 0 },
  ])("$what", async ({ write, revokes }) => {
    installRenderSeam(engine, async () => {
      await write();
      return undefined;
    });

    await expect(engine.useSecret(KEY, render(), ALICE)).resolves.toStrictEqual(RESULT);

    expect(callRows()).toStrictEqual({
      key: [{ detail: k({ written: "yes" }), success: true }],
      slots: SLOTS.map(() => [{ detail: s(), success: true }]),
    });
    const revoked = engine.queryAudit({ eventType: AuditEventType.SECRET_REVOKE });
    expect(revoked).toHaveLength(revokes);
    expect(revoked.every((row) => row.principal_id === null)).toBe(true);
  });
});
