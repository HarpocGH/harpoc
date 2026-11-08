import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  chownSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { Worker } from "node:worker_threads";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import {
  TokenRotationScheduler,
  WIN32_RENAME_ATTEMPTS,
  WIN32_RENAME_RETRY_MS,
  writeTokenFile,
} from "./token-rotation.js";
import type {
  TokenRotationEngine,
  TokenRotationSchedulerOptions,
  TokenRotationSpec,
} from "./token-rotation.js";
import { VaultEngine } from "../vault-engine.js";
import { registerAgents } from "../__fixtures__/engine-seams.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("../crypto/argon2.js", async (importOriginal) =>
  (await import("../__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

/** Half of the specs' default 10-minute lifetime: the re-mint delay. */
const HALF = 300_000;

type OnError = NonNullable<TokenRotationSchedulerOptions["onError"]>;
type OnRotate = NonNullable<TokenRotationSchedulerOptions["onRotate"]>;

let dir: string;
let engine: VaultEngine | undefined;
const schedulers: TokenRotationScheduler[] = [];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-rotation-"));
});

afterEach(async () => {
  for (const scheduler of schedulers.splice(0)) await scheduler.stop();
  vi.restoreAllMocks();
  vi.useRealTimers();
  await engine?.destroy();
  engine = undefined;
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/** A three-segment token with a known `jti` and a random signature segment — enough to decode, never verified. */
function fakeJwt(jti: string): string {
  const segment = (value: object): string =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${segment({ alg: "HS256", typ: "JWT" })}.${segment({ jti, exp: 4_102_444_800 })}.${randomBytes(32).toString("base64url")}`;
}

interface EngineDouble {
  engine: TokenRotationEngine;
  createToken: Mock<TokenRotationEngine["createToken"]>;
  /** Every token the double handed out, in order — the needles of the leak sweep. */
  minted: string[];
  /** Every later mint for `agent` throws `err`. */
  refuse(agent: string, err: VaultError): void;
  callsFor(agent: string): number;
}

function engineDouble(): EngineDouble {
  const minted: string[] = [];
  const refusals = new Map<string, VaultError>();
  let serial = 0;
  const createToken = vi.fn<TokenRotationEngine["createToken"]>((subject) => {
    const refusal = refusals.get(subject);
    if (refusal) throw refusal;
    serial += 1;
    const token = fakeJwt(`jti-${subject}-${serial}`);
    minted.push(token);
    return token;
  });
  return {
    engine: { createToken },
    createToken,
    minted,
    refuse: (agent, err) => {
      refusals.set(agent, err);
    },
    callsFor: (agent) => createToken.mock.calls.filter(([subject]) => subject === agent).length,
  };
}

function consumerDir(name: string): string {
  const path = join(dir, name);
  mkdirSync(path, { recursive: true });
  return path;
}

function specFor(agent: string, overrides: Partial<TokenRotationSpec> = {}): TokenRotationSpec {
  return {
    agent,
    file: join(consumerDir(agent), "token.jwt"),
    scope: ["use"],
    secrets: ["db-*"],
    ttlMinutes: 10,
    ...overrides,
  };
}

function scheduler(
  rotationEngine: TokenRotationEngine,
  specs: TokenRotationSpec[],
  options?: TokenRotationSchedulerOptions,
): TokenRotationScheduler {
  const created = new TokenRotationScheduler(rotationEngine, specs, options);
  schedulers.push(created);
  return created;
}

/** Boolean-shaped, so a failure never prints a token. */
function holds(file: string, token: string | undefined): boolean {
  return token !== undefined && readFileSync(file, "utf8") === `${token}\n`;
}

function temporariesIn(path: string): string[] {
  return readdirSync(path).filter((name) => name.endsWith(".tmp"));
}

function mintOptions(previousJti?: string): Record<string, unknown> {
  return {
    principalType: "agent",
    secrets: ["db-*"],
    label: "rotation",
    rotation: previousJti === undefined ? {} : { previousJti },
  };
}

describe("TokenRotationScheduler on a recording engine double", () => {
  it("start() mints every spec once, at once, and writes each token to its file", async () => {
    const double = engineDouble();
    const bot = specFor("bot");
    const ci = specFor("ci", { scope: ["use", "read"], secrets: ["api-*"], ttlMinutes: 1440 });
    const onRotate = vi.fn<OnRotate>();

    await scheduler(double.engine, [bot, ci], { onRotate }).start();

    expect(double.createToken.mock.calls).toEqual([
      ["bot", ["use"], 600_000, mintOptions()],
      [
        "ci",
        ["use", "read"],
        86_400_000,
        { principalType: "agent", secrets: ["api-*"], label: "rotation", rotation: {} },
      ],
    ]);
    expect(holds(bot.file, double.minted[0])).toBe(true);
    expect(holds(ci.file, double.minted[1])).toBe(true);
    expect(onRotate.mock.calls).toEqual([
      [bot, "jti-bot-1"],
      [ci, "jti-ci-2"],
    ]);
  });

  it("re-mints at exactly half the TTL and not before, naming the token it replaces", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const bot = specFor("bot");
    await scheduler(double.engine, [bot]).start();

    await vi.advanceTimersByTimeAsync(HALF - 1);
    expect(double.createToken).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1);
    expect(double.createToken).toHaveBeenCalledTimes(2);
    expect(double.createToken.mock.calls[1]).toEqual([
      "bot",
      ["use"],
      600_000,
      mintOptions("jti-bot-1"),
    ]);
    expect(holds(bot.file, double.minted[1])).toBe(true);

    await vi.advanceTimersByTimeAsync(HALF);
    expect(double.createToken).toHaveBeenCalledTimes(3);
    expect(double.createToken.mock.calls[2]?.[3]).toEqual(mintOptions("jti-bot-2"));
    expect(holds(bot.file, double.minted[2])).toBe(true);
  });

  it("re-mints a 1440-minute token every 12 hours", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    await scheduler(double.engine, [specFor("bot", { ttlMinutes: 1440 })]).start();

    await vi.advanceTimersByTimeAsync(43_200_000 - 1);
    expect(double.createToken).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(double.createToken).toHaveBeenCalledTimes(2);
  });

  it("arms one timer per spec, unref'd so the rotation never holds the process open", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const armed = vi.spyOn(globalThis, "setTimeout");

    await scheduler(double.engine, [specFor("bot"), specFor("ci")]).start();

    expect(vi.getTimerCount()).toBe(2);
    expect(armed).toHaveBeenCalledTimes(2);
    expect(armed.mock.results.map((result) => (result.value as NodeJS.Timeout).hasRef())).toEqual([
      false,
      false,
    ]);
  });

  it("stop() clears every armed re-mint: nothing is minted after it", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const rotation = scheduler(double.engine, [specFor("bot"), specFor("ci")]);
    await rotation.start();

    await rotation.stop();
    await vi.advanceTimersByTimeAsync(10 * HALF);

    expect(vi.getTimerCount()).toBe(0);
    expect(double.createToken).toHaveBeenCalledTimes(2);
  });

  it("start() is a no-op while running", async () => {
    const double = engineDouble();
    const rotation = scheduler(double.engine, [specFor("bot")]);

    await rotation.start();
    await rotation.start();

    expect(double.createToken).toHaveBeenCalledTimes(1);
  });

  it("start() after stop() mints every spec afresh, naming no replaced token, as a daemon restart does", async () => {
    const double = engineDouble();
    const rotation = scheduler(double.engine, [specFor("bot")]);

    await rotation.start();
    await rotation.stop();
    await rotation.start();

    expect(double.createToken.mock.calls.map((call) => call[3].rotation)).toEqual([{}, {}]);
  });

  it("rotateNow() re-mints every live spec now and re-arms each from then", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const bot = specFor("bot");
    const rotation = scheduler(double.engine, [bot]);
    await rotation.start();
    await vi.advanceTimersByTimeAsync(100_000);

    await rotation.rotateNow();
    expect(double.createToken).toHaveBeenCalledTimes(2);
    expect(double.createToken.mock.calls[1]?.[3]).toEqual(mintOptions("jti-bot-1"));
    expect(holds(bot.file, double.minted[1])).toBe(true);

    await vi.advanceTimersByTimeAsync(HALF - 1);
    expect(double.createToken).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(double.createToken).toHaveBeenCalledTimes(3);
  });

  const refusals = [
    ["TOKEN_REVOKED", VaultError.tokenRevoked()],
    ["AGENT_INACTIVE", VaultError.agentInactive("bot")],
    ["AGENT_NOT_FOUND", VaultError.agentNotFound("bot")],
  ] as const;

  it.each(refusals)(
    "%s from the engine stops that spec alone: one onError, no re-arm, the other spec rotates on",
    async (_code, refusal) => {
      vi.useFakeTimers();
      const double = engineDouble();
      const bot = specFor("bot");
      const ci = specFor("ci");
      const onError = vi.fn<OnError>();
      await scheduler(double.engine, [bot, ci], { onError }).start();
      double.refuse("bot", refusal);

      await vi.advanceTimersByTimeAsync(HALF);
      expect(onError.mock.calls).toEqual([[bot, refusal]]);
      expect(vi.getTimerCount()).toBe(1);

      await vi.advanceTimersByTimeAsync(3 * HALF);
      expect(double.callsFor("bot")).toBe(2);
      expect(double.callsFor("ci")).toBe(5);
      expect(onError).toHaveBeenCalledTimes(1);
      expect(holds(bot.file, double.minted[0])).toBe(true);
    },
  );

  it("VAULT_LOCKED stops every spec: one onError, no timer left", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const bot = specFor("bot");
    const ci = specFor("ci");
    const onError = vi.fn<OnError>();
    await scheduler(double.engine, [bot, ci], { onError }).start();
    const locked = VaultError.vaultLocked();
    double.refuse("bot", locked);
    double.refuse("ci", locked);

    await vi.advanceTimersByTimeAsync(HALF);
    expect(onError.mock.calls).toEqual([[bot, locked]]);
    expect(vi.getTimerCount()).toBe(0);

    await vi.advanceTimersByTimeAsync(10 * HALF);
    expect(double.callsFor("bot")).toBe(2);
    expect(double.callsFor("ci")).toBe(1);
  });

  it("a consumer directory that is gone stops the spec with FILE_IO_ERROR and mints nothing", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const bot = specFor("bot");
    const onError = vi.fn<OnError>();
    await scheduler(double.engine, [bot], { onError }).start();
    rmSync(join(dir, "bot"), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });

    await vi.advanceTimersByTimeAsync(HALF);

    expect(double.createToken).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledTimes(1);
    const [, err] = onError.mock.calls[0] ?? [];
    expect(err).toBeInstanceOf(VaultError);
    expect((err as VaultError).code).toBe(ErrorCode.FILE_IO_ERROR);
    expect((err as VaultError).message).toContain(bot.file);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a rename that fails after the mint removes its temporary and stops the spec with FILE_IO_ERROR", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const bot = specFor("bot");
    const onError = vi.fn<OnError>();
    await scheduler(double.engine, [bot], { onError }).start();
    rmSync(bot.file);
    mkdirSync(bot.file);
    writeFileSync(join(bot.file, "occupant"), "x");

    await vi.advanceTimersByTimeAsync(HALF);

    expect(double.createToken).toHaveBeenCalledTimes(2);
    expect((onError.mock.calls[0]?.[1] as VaultError).code).toBe(ErrorCode.FILE_IO_ERROR);
    expect(temporariesIn(join(dir, "bot"))).toEqual([]);
    expect(readdirSync(bot.file)).toEqual(["occupant"]);
  });

  it("start() rejects with the first refusal, clears every timer and leaves the earlier files as written", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const bot = specFor("bot");
    const ci = specFor("ci");
    const onError = vi.fn<OnError>();
    double.refuse("ci", VaultError.agentNotFound("ci"));

    await expectVaultError(
      () => scheduler(double.engine, [bot, ci], { onError }).start(),
      ErrorCode.AGENT_NOT_FOUND,
    );

    expect(holds(bot.file, double.minted[0])).toBe(true);
    expect(existsSync(ci.file)).toBe(false);
    expect(temporariesIn(join(dir, "ci"))).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
    expect(onError).not.toHaveBeenCalled();
  });

  it("start() with a file it cannot create rejects FILE_IO_ERROR naming the path and mints nothing", async () => {
    const double = engineDouble();
    const file = join(dir, "missing", "token.jwt");

    const err = await expectVaultError(
      () => scheduler(double.engine, [specFor("bot", { file })]).start(),
      ErrorCode.FILE_IO_ERROR,
    );

    expect(err.message).toBe(`could not write the token file ${file} (ENOENT)`);
    expect(double.createToken).not.toHaveBeenCalled();
  });

  it("refuses a ttl outside 1–1440 whole minutes and two specs naming one file, before any mint", async () => {
    const double = engineDouble();
    for (const ttlMinutes of [0, 1441, 1.5, Number.NaN]) {
      await expectVaultError(
        () => new TokenRotationScheduler(double.engine, [specFor("bot", { ttlMinutes })]),
        ErrorCode.INVALID_INPUT,
      );
    }
    const bot = specFor("bot");
    const err = await expectVaultError(
      () => new TokenRotationScheduler(double.engine, [bot, { ...specFor("ci"), file: bot.file }]),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toContain("one token file per spec");
    expect(double.createToken).not.toHaveBeenCalled();
  });

  it("a callback that throws does not stop the rotation", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const onRotate = vi.fn<OnRotate>(() => {
      throw new Error("host callback failed");
    });
    await scheduler(double.engine, [specFor("bot")], { onRotate }).start();

    await vi.advanceTimersByTimeAsync(2 * HALF);

    expect(double.createToken).toHaveBeenCalledTimes(3);
    expect(onRotate).toHaveBeenCalledTimes(3);
  });

  it("never hands a token to a callback or an error — a minted token that was never written included", async () => {
    vi.useFakeTimers();
    const double = engineDouble();
    const bot = specFor("bot");
    const ci = specFor("ci");
    const ops = specFor("ops");
    const seen: unknown[] = [];
    const record = (...args: unknown[]): void => {
      seen.push(...args);
    };
    await scheduler(double.engine, [bot, ci, ops], { onError: record, onRotate: record }).start();
    await vi.advanceTimersByTimeAsync(HALF);
    double.refuse("bot", VaultError.tokenRevoked());
    rmSync(ci.file);
    mkdirSync(ci.file);
    writeFileSync(join(ci.file, "occupant"), "x");
    rmSync(join(dir, "ops"), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await vi.advanceTimersByTimeAsync(HALF);

    const text = seen
      .map((value) =>
        value instanceof Error
          ? `${value.name} ${value.message} ${String(value.stack)}`
          : JSON.stringify(value),
      )
      .join("\n");
    const needles = double.minted.flatMap((token) => [token, token.split(".")[2] ?? token]);
    expect(double.minted.length).toBe(7);
    expect(seen.length).toBe(18);
    expect(needles.some((needle) => text.includes(needle))).toBe(false);
  });
});

describe("writeTokenFile", () => {
  it("writes the token and one newline — the bytes `auth token --out` writes — which a trimming reader gets back whole", () => {
    const file = join(consumerDir("bot"), "token.jwt");
    const token = fakeJwt("jti-1");

    writeTokenFile(file, token);

    const bytes = readFileSync(file);
    expect(bytes.equals(Buffer.from(`${token}\n`, "utf8"))).toBe(true);
    expect(bytes.toString("utf8").trim() === token).toBe(true);
  });

  it("replaces the previous token in place and leaves no temporary beside it", () => {
    const consumer = consumerDir("bot");
    const file = join(consumer, "token.jwt");
    writeTokenFile(file, fakeJwt("jti-1"));
    const second = fakeJwt("jti-2");

    writeTokenFile(file, second);

    expect(holds(file, second)).toBe(true);
    expect(readdirSync(consumer)).toEqual(["token.jwt"]);
  });

  it("refuses a missing directory FILE_IO_ERROR naming the path, never the token", async () => {
    const file = join(dir, "missing", "token.jwt");
    const token = fakeJwt("jti-1");

    const err = await expectVaultError(() => writeTokenFile(file, token), ErrorCode.FILE_IO_ERROR);

    expect(err.message).toBe(`could not write the token file ${file} (ENOENT)`);
    expect(err.message.includes(token)).toBe(false);
  });

  // POSIX: on win32 the mode bits are not the file's access control (statSync reports 0o666).
  it.skipIf(process.platform === "win32")(
    "creates the file 0640 whatever the umask (fchmod after the open)",
    () => {
      const file = join(consumerDir("bot"), "token.jwt");
      const previous = process.umask(0o077);
      try {
        writeTokenFile(file, fakeJwt("jti-1"));
      } finally {
        process.umask(previous);
      }

      expect(statSync(file).mode & 0o7777).toBe(0o640);
    },
  );

  // POSIX: R-E1a's set-group-ID consumer directory; with a supplementary group the directory is
  // first given that group, so the row tells inheritance from the process's own group.
  it.skipIf(process.platform === "win32")(
    "takes the group of a set-group-ID directory, as in the consumer directory's 02750",
    () => {
      const consumer = consumerDir("bot");
      const other = (process.getgroups?.() ?? []).find((gid) => gid !== process.getegid?.());
      if (other !== undefined) chownSync(consumer, statSync(consumer).uid, other);
      chmodSync(consumer, 0o2750);
      const file = join(consumer, "token.jwt");

      writeTokenFile(file, fakeJwt("jti-1"));

      expect(statSync(file).gid).toBe(statSync(consumer).gid);
    },
  );

  // POSIX: rename(2) replaces the path atomically. On win32 a rename over a file another handle
  // holds open fails EPERM (measured, Node v24.13.1) and the write is refused — B5 refuses
  // --issue-token on win32 (RA-B5-4).
  it.skipIf(process.platform === "win32")(
    "a reader on another thread sees only whole tokens while the file is replaced",
    async () => {
      const file = join(consumerDir("bot"), "token.jwt");
      writeTokenFile(file, fakeJwt("jti-0"));
      const counters = new Int32Array(new SharedArrayBuffer(12));
      const reader = new Worker(
        [
          'const { readFileSync } = require("node:fs");',
          'const { parentPort, workerData } = require("node:worker_threads");',
          "const { file, counters } = workerData;",
          "const whole = /^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\n$/;",
          "let posted = false;",
          "while (Atomics.load(counters, 0) === 0) {",
          '  let text = "";',
          '  try { text = readFileSync(file, "utf8"); } catch { text = ""; }',
          "  if (!whole.test(text)) Atomics.add(counters, 2, 1);",
          "  Atomics.add(counters, 1, 1);",
          '  if (!posted) { posted = true; parentPort.postMessage("reading"); }',
          "}",
        ].join("\n"),
        { eval: true, workerData: { file, counters } },
      );
      const exited = once(reader, "exit");
      await once(reader, "message");

      let writes = 0;
      try {
        while ((writes < 200 || Atomics.load(counters, 1) < 1_000) && writes < 5_000) {
          writes += 1;
          writeTokenFile(file, fakeJwt(`jti-${writes}`));
        }
      } finally {
        Atomics.store(counters, 0, 1);
      }
      const [exitCode] = await exited;

      expect(exitCode).toBe(0);
      expect(Atomics.load(counters, 1)).toBeGreaterThanOrEqual(1_000);
      expect(Atomics.load(counters, 2)).toBe(0);
    },
  );

  /**
   * Another process holding `file` open for `holdMs` — the writer's retry sleeps synchronously, so
   * an in-process holder could not let go. Resolves once the handle is open, with a promise of its
   * exit (wrapped: an async function returning the bare promise would adopt it and wait for the exit).
   */
  async function holdOpen(file: string, holdMs: number): Promise<{ exited: Promise<unknown> }> {
    const holder = spawn(
      process.execPath,
      [
        "-e",
        `const fs=require("fs");const fd=fs.openSync(process.argv[1],"r");process.stdout.write("open");setTimeout(()=>fs.closeSync(fd),${String(holdMs)})`,
        file,
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    const exited = once(holder, "close");
    const opened = await Promise.race([
      once(holder.stdout, "data").then(() => true),
      exited.then(() => false),
    ]);
    if (!opened) {
      const [code] = (await exited) as [number | null];
      throw new Error(`the holder exited (code ${String(code)}) before it held ${file} open`);
    }
    return { exited };
  }

  // RP-B7-3: on win32 the rename over a held file fails EPERM (MoveFileExW); a reader that lets
  // go within WIN32_RENAME_ATTEMPTS × WIN32_RENAME_RETRY_MS is waited out.
  it.runIf(process.platform === "win32")(
    "win32: a reader holding the token file open for 150 ms delays the rename, which then lands",
    async () => {
      const consumer = consumerDir("bot");
      const file = join(consumer, "token.jwt");
      writeTokenFile(file, fakeJwt("jti-1"));
      const { exited } = await holdOpen(file, 150);
      const second = fakeJwt("jti-2");

      writeTokenFile(file, second);

      await exited;
      expect(holds(file, second)).toBe(true);
      expect(readdirSync(consumer)).toEqual(["token.jwt"]);
    },
  );

  it.runIf(process.platform === "win32")(
    "win32: a reader holding it past the retries refuses FILE_IO_ERROR naming the path and EPERM; the old token stays, no temporary left",
    async () => {
      const consumer = consumerDir("bot");
      const file = join(consumer, "token.jwt");
      const first = fakeJwt("jti-1");
      writeTokenFile(file, first);
      const { exited } = await holdOpen(file, 3_000);
      const second = fakeJwt("jti-2");

      const started = Date.now();
      const err = await expectVaultError(
        () => writeTokenFile(file, second),
        ErrorCode.FILE_IO_ERROR,
      );
      const waited = Date.now() - started;

      await exited;
      expect(err.message).toBe(`could not write the token file ${file} (EPERM)`);
      expect(err.message.includes(second)).toBe(false);
      expect(waited).toBeGreaterThanOrEqual((WIN32_RENAME_ATTEMPTS - 1) * WIN32_RENAME_RETRY_MS);
      expect(holds(file, first)).toBe(true);
      expect(readdirSync(consumer)).toEqual(["token.jwt"]);
    },
  );
});

describe("TokenRotationScheduler on a real engine", () => {
  async function openEngine(...agents: string[]): Promise<VaultEngine> {
    const opened = new VaultEngine({
      dbPath: join(dir, "test.vault.db"),
      sessionPath: join(dir, "session.json"),
    });
    engine = opened;
    await opened.initVault("password");
    registerAgents(opened, ...agents);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    return opened;
  }

  function tokenIn(file: string): string {
    return readFileSync(file, "utf8").trim();
  }

  function rotationRows(live: VaultEngine, success: boolean): Record<string, unknown>[] {
    return live
      .queryAudit({ eventType: AuditEventType.TOKEN_CREATE, success })
      .map((row) => row.detail ?? {});
  }

  it("mints a token the engine verifies, its token.create row carrying rotation: true and the jti", async () => {
    const live = await openEngine("bot");
    const bot = specFor("bot");

    await scheduler(live, [bot]).start();

    const claims = live.verifyToken(tokenIn(bot.file));
    expect(claims).toMatchObject({
      sub: "bot",
      scope: ["use"],
      secrets: ["db-*"],
      principal_type: "agent",
    });
    expect(claims.exp - claims.iat).toBe(600);
    expect(rotationRows(live, true)).toEqual([
      {
        subject: "bot",
        jti: claims.jti,
        scope: ["use"],
        principal_type: "agent",
        label: "rotation",
        rotation: true,
      },
    ]);
    expect(live.listIssuedTokens()[0]?.label).toBe("rotation");
  });

  it("re-mints at half the TTL; the replaced token stays valid until its own expiry", async () => {
    const live = await openEngine("bot");
    const bot = specFor("bot");
    await scheduler(live, [bot]).start();
    const first = tokenIn(bot.file);

    await vi.advanceTimersByTimeAsync(HALF);

    const second = tokenIn(bot.file);
    expect(second === first).toBe(false);
    expect(live.verifyToken(second).sub).toBe("bot");
    expect(live.verifyToken(first).sub).toBe("bot");
    // The audit listing is newest first.
    expect(rotationRows(live, true).map((row) => row.jti)).toEqual([
      live.verifyToken(second).jti,
      live.verifyToken(first).jti,
    ]);
  });

  it("does not re-mint a revoked jti: a failed token.create row, one onError, the spec stopped", async () => {
    const live = await openEngine("bot");
    const bot = specFor("bot");
    const onError = vi.fn<OnError>();
    await scheduler(live, [bot], { onError }).start();
    const revoked = tokenIn(bot.file);
    live.revokeToken(live.verifyToken(revoked).jti);

    await vi.advanceTimersByTimeAsync(HALF);

    expect(onError).toHaveBeenCalledTimes(1);
    expect((onError.mock.calls[0]?.[1] as VaultError).code).toBe(ErrorCode.TOKEN_REVOKED);
    expect(rotationRows(live, false)).toEqual([
      { subject: "bot", principal_type: "agent", rotation: true, error: "TOKEN_REVOKED" },
    ]);
    expect(rotationRows(live, true)).toHaveLength(1);
    expect(tokenIn(bot.file) === revoked).toBe(true);
    await expectVaultError(() => live.verifyToken(revoked), ErrorCode.TOKEN_REVOKED);

    await vi.advanceTimersByTimeAsync(4 * HALF);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(rotationRows(live, false)).toHaveLength(1);
  });

  it("stops at the next tick with AGENT_INACTIVE once the agent is deactivated", async () => {
    const live = await openEngine("bot");
    const bot = specFor("bot");
    const onError = vi.fn<OnError>();
    await scheduler(live, [bot], { onError }).start();

    live.deactivateAgent("bot");
    await vi.advanceTimersByTimeAsync(HALF);

    expect(onError).toHaveBeenCalledTimes(1);
    expect((onError.mock.calls[0]?.[1] as VaultError).code).toBe(ErrorCode.AGENT_INACTIVE);
    expect(rotationRows(live, false).map((row) => row.error)).toEqual(["AGENT_INACTIVE"]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("stops at the next tick with AGENT_NOT_FOUND once the agent is deleted", async () => {
    const live = await openEngine("bot");
    const bot = specFor("bot");
    const onError = vi.fn<OnError>();
    await scheduler(live, [bot], { onError }).start();

    live.deleteAgent("bot");
    await vi.advanceTimersByTimeAsync(HALF);

    expect(onError).toHaveBeenCalledTimes(1);
    expect((onError.mock.calls[0]?.[1] as VaultError).code).toBe(ErrorCode.AGENT_NOT_FOUND);
    expect(rotationRows(live, false).map((row) => row.error)).toEqual(["AGENT_NOT_FOUND"]);
  });

  it("stops every spec when lock() sealed the engine, writing no row", async () => {
    const live = await openEngine("bot", "ci");
    const bot = specFor("bot");
    const onError = vi.fn<OnError>();
    await scheduler(live, [bot, specFor("ci")], { onError }).start();

    await live.lock();
    await vi.advanceTimersByTimeAsync(HALF);

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]?.[0]).toBe(bot);
    expect((onError.mock.calls[0]?.[1] as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    expect(vi.getTimerCount()).toBe(0);
    await live.unlock("password");
    expect(rotationRows(live, false)).toEqual([]);
    expect(rotationRows(live, true)).toHaveLength(2);
  });
});
