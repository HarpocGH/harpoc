import { randomBytes } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, UseSecretAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode, PrincipalType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import {
  installRenderSeam,
  nonReadAuditCount,
  registerAgents,
  seedLiveStdioEntry,
} from "./__fixtures__/engine-seams.js";
import { resolveNativeSshClient } from "./injection/__fixtures__/native-ssh-client.js";
import { approval, ENTRY, keyPolicy } from "./injection/__fixtures__/render-entries.js";
import { controlledPathDirs } from "./injection/allowlist.js";
import type { RenderControl } from "./injection/sftp-render.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { system32Path } from "./win32-paths.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// A seal under a render is met past the render's client resolution; on Windows only the native
// Win32-OpenSSH client is accepted, so its directory leads the PATH. A host without one skips.
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}
const SSH = resolveNativeSshClient("ssh");
const describeSsh = describe.skipIf(SSH === null);

const KEY = "secret://deploy-key";
const BOT = "secret://bot-token";
const API = "secret://api-key";
const DB = "secret://db-pass";
const SLOTS = [BOT, API, DB];
const RESULT = { type: "sftp_render", status: "written" };
const RENDER = { type: "sftp", operation: "render", entry: "env" } as UseSecretAction;
const ALICE: CallerContext = { principal_type: "agent", principal_id: "alice", interface: "rest" };
const ISO = { network_isolation: false, fs_isolation: false };
const REST = { interface: "rest" };
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

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;
let second: VaultEngine | undefined;
let keyId: string;
let ids: Record<string, string>;

interface EngineInternals {
  secretManager: SecretManager;
  store: SqliteStore;
  renderHolds: Set<string>;
  kek: Uint8Array | null;
}

function internals(): EngineInternals {
  return engine as unknown as EngineInternals;
}

function draw(): string {
  return randomBytes(18).toString("hex");
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

async function makeSecret(handle: string): Promise<string> {
  await engine.createSecret({
    name: handle.slice("secret://".length),
    type: "api_key",
    value: new Uint8Array(Buffer.from(draw())),
  });
  return engine.resolveSecretId(handle);
}

/** The four rows of a render the seal recorded, read through `at`. */
function sealedRows(written: string, at: VaultEngine = engine) {
  const rows = at.queryAudit({ eventType: AuditEventType.SECRET_USE }).reverse();
  expect(
    rows.map((row) => ({ secret: row.secret_id, success: row.success, detail: row.detail })),
  ).toStrictEqual([
    {
      secret: keyId,
      success: false,
      detail: {
        ...R,
        slots: SLOTS,
        written,
        ...ISO,
        error: ErrorCode.VAULT_LOCKED,
        ...REST,
      },
    },
    ...SLOTS.map((handle) => ({
      secret: ids[handle],
      success: false,
      detail: { ...S, ...ISO, error: ErrorCode.VAULT_LOCKED, ...REST },
    })),
  ]);
}

/** A render whose `run` waits until `release`, `entered` once it is in `run`. */
function startWaiting(before?: (control: RenderControl) => void) {
  const gate = deferred<undefined>();
  const entered = deferred<RenderControl>();
  let answer: () => unknown = () => undefined;
  const calls = installRenderSeam(engine, async (_plan, control) => {
    before?.(control);
    entered.resolve(control);
    await gate.promise;
    return answer();
  });
  const pending = quiet(engine.useSecret(KEY, RENDER, ALICE));
  return {
    calls,
    pending,
    entered: entered.promise,
    release: (then: () => unknown = () => undefined) => {
      answer = then;
      gate.resolve(undefined);
    },
  };
}

// vault-engine.sftp-render.test.ts's engine-building hook, the same as this one, ran past core's
// 30 s on the loaded windows-latest Node 24 leg (ci.yml run 45594869586).
const HOOK_TIMEOUT_MS = 120_000;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-seal-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
  await engine.initVault("password");
  keyId = await makeSecret(KEY);
  ids = { [KEY]: keyId };
  for (const handle of SLOTS) ids[handle] = await makeSecret(handle);
  await engine.setInjectionPolicy(KEY, keyPolicy([ENTRY]));
  for (const handle of SLOTS) {
    await engine.setInjectionPolicy(handle, {
      render: { entries: [], approvals: [approval(keyId, ENTRY)] },
    });
  }
  registerAgents(engine, "alice");
  for (const id of Object.values(ids)) {
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
}, HOOK_TIMEOUT_MS);

afterEach(async () => {
  vi.restoreAllMocks();
  try {
    await second?.destroy();
    second = undefined;
    await engine.unlock("password");
    expect(engine.verifyAuditChain().valid).toBe(true);
  } finally {
    await engine.destroy();
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}, HOOK_TIMEOUT_MS);

describeSsh("a seal under a render", () => {
  it.each([
    {
      what: "during the version read",
      arrange: (locked: (count: number) => void) => {
        installRenderSeam(engine, undefined, {
          refuseOldClient: async () => {
            await engine.lock();
            locked(nonReadAuditCount(engine));
          },
        });
      },
    },
    {
      what: "during a slot's resolution",
      arrange: (locked: (count: number) => void) => {
        installRenderSeam(engine);
        const manager = internals().secretManager;
        const resolve = manager.resolveHandle.bind(manager);
        manager.resolveHandle = async (handle: string) => {
          if (handle === API) {
            await engine.lock();
            locked(nonReadAuditCount(engine));
          }
          return resolve(handle);
        };
      },
    },
  ])(
    "a lock before the registration answers VAULT_LOCKED and writes nothing — $what",
    async ({ arrange }) => {
      let count = -1;
      arrange((at) => {
        count = at;
      });
      const decrypt = vi.spyOn(internals().secretManager, "getSecretValue");

      await expectVaultError(() => engine.useSecret(KEY, RENDER, ALICE), ErrorCode.VAULT_LOCKED);

      expect(nonReadAuditCount(engine)).toBe(count);
      expect(decrypt).not.toHaveBeenCalled();
      expect(internals().renderHolds.size).toBe(0);
      await engine.unlock("password");
      installRenderSeam(engine);
      await expect(engine.useSecret(KEY, RENDER, ALICE)).resolves.toStrictEqual(RESULT);
    },
  );

  it("a lock during the handle's own ladder answers VAULT_LOCKED before step 2 writes a row", async () => {
    const calls = installRenderSeam(engine);
    const at = engine as unknown as {
      refuseOnBootstrapMark: (...args: unknown[]) => Promise<void>;
    };
    const original = at.refuseOnBootstrapMark.bind(engine);
    let count = -1;
    vi.spyOn(at, "refuseOnBootstrapMark").mockImplementation(async (...args: unknown[]) => {
      await engine.lock();
      count = nonReadAuditCount(engine);
      return original(...args);
    });

    await expectVaultError(
      () => engine.useSecret(KEY, { ...RENDER, entry: "nope" } as UseSecretAction, ALICE),
      ErrorCode.VAULT_LOCKED,
    );

    expect(nonReadAuditCount(engine)).toBe(count);
    expect(calls).toHaveLength(0);
  });

  it.each([
    { target: KEY, when: "before the value" },
    { target: KEY, when: "after the value" },
    { target: BOT, when: "before the value" },
    { target: DB, when: "after the value" },
  ])("a lock during the decrypt of $target, $when", async ({ target, when }) => {
    const calls = installRenderSeam(engine);
    const manager = internals().secretManager;
    const decrypt = manager.getSecretValue.bind(manager);
    const retained: Uint8Array[] = [];
    manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      if (args[0] === target && when === "before the value") await engine.lock();
      const value = await decrypt(...args);
      retained.push(value);
      if (args[0] === target && when === "after the value") await engine.lock();
      return value;
    };

    await expectVaultError(() => engine.useSecret(KEY, RENDER, ALICE), ErrorCode.VAULT_LOCKED);

    expect(calls).toHaveLength(0);
    expect(retained.every(allZero)).toBe(true);
    expect(internals().renderHolds.size).toBe(0);
    await engine.unlock("password");
    sealedRows("no");
  });

  it.each([
    { what: "answers written", then: () => undefined },
    {
      what: "answers a failure",
      then: () => ({
        kind: "ran",
        outcome: { written: "no", reason: "connect" },
        spawn: ISO,
      }),
    },
    {
      what: "throws",
      then: () => {
        throw new Error("the child was cut");
      },
    },
  ])(
    "a lock under the write aborts the child and leaves the rows; run then $what",
    async ({ then }) => {
      const { pending, entered, release } = startWaiting();
      const control = await entered;

      await engine.lock();
      expect(control.signal.aborted).toBe(true);
      await engine.unlock("password");
      sealedRows("no");
      const count = nonReadAuditCount(engine);
      release(then);

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      expect(nonReadAuditCount(engine)).toBe(count);
      expect(internals().renderHolds.size).toBe(0);
    },
  );

  it("the row holds what the writer last reported", async () => {
    const { pending, entered, release } = startWaiting((control) => {
      control.written = "unconfirmed";
    });
    await entered;

    await engine.lock();
    release();

    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
    await engine.unlock("password");
    sealedRows("unconfirmed");
  });

  it.each([
    {
      what: "locked and unlocked again",
      seal: async () => {
        await engine.lock();
        await engine.unlock("password");
      },
    },
    { what: "unlocked again over the live engine", seal: () => engine.unlock("password") },
  ])("$what: four rows once, nothing after", async ({ seal }) => {
    const { pending, entered, release } = startWaiting();
    await entered;

    await seal();
    const count = nonReadAuditCount(engine);
    release();

    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
    expect(nonReadAuditCount(engine)).toBe(count);
    sealedRows("no");
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("destroyed: a second engine reads the four rows once, nothing after", async () => {
    const { pending, entered, release } = startWaiting();
    await entered;

    await engine.destroy();
    release();

    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
    second = new VaultEngine({ dbPath, sessionPath: join(tempDir, "second-session.json") });
    await second.unlock("password");
    sealedRows("no", second);
  });

  it("the write ending while lock() still waits", async () => {
    const closing = deferred<undefined>();
    const closeGate = deferred<undefined>();
    await seedLiveStdioEntry(engine, keyId, () => {
      closing.resolve(undefined);
      return closeGate.promise;
    });
    const { pending, entered, release } = startWaiting();
    const control = await entered;
    const locking = engine.lock();
    await closing.promise;

    release(() => {
      control.written = "yes";
      return undefined;
    });

    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
    closeGate.resolve(undefined);
    await locking;
    await engine.unlock("password");
    sealedRows("yes");
  });

  it("a seal whose rows cannot be written goes on", async () => {
    const { pending, entered, release } = startWaiting();
    await entered;
    const live = internals().store;
    const insert = live.insertAuditEvent.bind(live);
    let inserts = 0;
    vi.spyOn(live, "insertAuditEvent").mockImplementation(
      (...args: Parameters<SqliteStore["insertAuditEvent"]>) => {
        inserts += 1;
        if (inserts === 2) throw new Error("audit unavailable");
        return insert(...args);
      },
    );

    await engine.lock();
    expect(internals().kek).toBeNull();
    release();

    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
    await engine.unlock("password");
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_USE })).toStrictEqual([]);
  });

  it("after a seal the path is held until the run has settled", async () => {
    const { pending, entered, release } = startWaiting();
    await entered;
    await engine.lock();
    await engine.unlock("password");

    await expectVaultError(() => engine.useSecret(KEY, RENDER, ALICE), ErrorCode.RENDER_IN_FLIGHT);
    release();
    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);

    installRenderSeam(engine);
    await expect(engine.useSecret(KEY, RENDER, ALICE)).resolves.toStrictEqual(RESULT);
  });
});
