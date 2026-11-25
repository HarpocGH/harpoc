import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ErrorCode } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { STDIN_ECHO_SCRIPT, untilWritten } from "./__fixtures__/spawn-children.js";
import { forceFsIsolationUnavailableForTests, requireFsIsolation } from "./fs-isolation.js";
import { requireNetworkIsolation } from "./network-isolation.js";
import { spawnDuplex } from "./spawn-captured.js";
import type { DuplexChild, SpawnCapturedResult } from "./spawn-captured.js";

const ENV: Record<string, string> = {
  PATH: process.env.PATH ?? process.env.Path ?? "",
  ...(process.platform === "win32" && process.env.SystemRoot
    ? { SystemRoot: process.env.SystemRoot }
    : {}),
};
const ALPHA_VALUE = "alpha-value";
const BETA_VALUE = "beta-value";

const NODE = process.execPath;
const FOUR_MIB = 4 * 1024 * 1024;
const TWO_MIB = 2 * 1024 * 1024;
const ECHO = ["-e", STDIN_ECHO_SCRIPT];
const DIGEST = [
  "-e",
  'const h = require("node:crypto").createHash("sha256"); process.stdin.on("data", (c) => h.update(c)); process.stdin.on("end", () => process.stdout.write(h.digest("hex")));',
];

/**
 * The 256 byte values in order, 256 times, then `e2 82 ac` and `f0 9f 98 80`, in three
 * writes cut after `e2 82` and after `f0 9f 98`.
 */
function binaryWrites(): Buffer[] {
  const values = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  const whole = Buffer.concat([
    ...Array.from({ length: 256 }, () => values),
    Buffer.from([0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80]),
  ]);
  const afterE282 = 256 * 256 + 2;
  const afterF09F98 = afterE282 + 4;
  return [
    whole.subarray(0, afterE282),
    whole.subarray(afterE282, afterF09F98),
    whole.subarray(afterF09F98),
  ];
}

function consume(d: DuplexChild): Buffer[] {
  const got: Buffer[] = [];
  d.onData((chunk) => got.push(chunk));
  return got;
}

const isZero = (b: Buffer): boolean => b.every((x) => x === 0);
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== "ESRCH";
  }
};
async function untilGone(pid: number, deadlineMs = 10_000): Promise<boolean> {
  const deadline = Date.now() + deadlineMs;
  while (isAlive(pid)) {
    if (Date.now() >= deadline) return false;
    await sleep(250);
  }
  return true;
}

/** `spawn-captured.lifecycle.test.ts`'s waiting child: a grandchild on its stdio, its pid renamed into place whole. */
function grandchildScript(pidPath: string): string {
  const inner = "setTimeout(() => {}, 120000)";
  return `
    const { spawn } = require("node:child_process");
    const gc = spawn(process.execPath, ["-e", ${JSON.stringify(inner)}], {
      stdio: "inherit",
      windowsHide: true,
      detached: false,
    });
    const fs = require("node:fs"); fs.writeFileSync(${JSON.stringify(`${pidPath}.tmp`)}, String(gc.pid)); fs.renameSync(${JSON.stringify(`${pidPath}.tmp`)}, ${JSON.stringify(pidPath)});
    console.log("child-done");
    setTimeout(() => {}, 60000);
  `;
}

let dir: string;
/** The grandchild's pid when a case has read it and not yet seen it gone. */
let survivor: number | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-spawn-duplex-"));
});

afterEach(() => {
  vi.useRealTimers();
  forceFsIsolationUnavailableForTests(null);
  if (survivor !== undefined) {
    try {
      process.kill(survivor, "SIGKILL");
    } catch {
      // Already gone.
    }
    survivor = undefined;
  }
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("spawnDuplex — the two-way pipe beside spawnCaptured", () => {
  it("binary bytes both ways", async () => {
    const d = await spawnDuplex(NODE, ECHO, { env: ENV, timeoutMs: 20_000 });
    const got = consume(d);
    const writes = binaryWrites();
    const copy = Buffer.concat(writes);
    for (const chunk of writes) await d.write(chunk);
    d.end();
    const r = await d.settled;

    expect(Buffer.concat(got).equals(copy)).toBe(true);
    expect(got.every((chunk) => Buffer.isBuffer(chunk))).toBe(true);
    expect(r).toMatchObject({ exit_code: 0, stdout: "", truncated: false });
  }, 30_000);

  it("4 MiB arrive whole and each chunk is zeroed after its callback", async () => {
    const d = await spawnDuplex(NODE, DIGEST, { env: ENV, timeoutMs: 20_000 });
    const got = consume(d);
    const chunk = randomBytes(FOUR_MIB);
    const digest = createHash("sha256").update(chunk).digest("hex");
    await d.write(chunk);
    expect(isZero(chunk)).toBe(true);
    d.end();
    const r = await d.settled;

    expect(Buffer.concat(got).toString()).toBe(digest);
    expect(r.exit_code).toBe(0);
  }, 30_000);

  it("the output is the consumer's alone, never capped", async () => {
    const d = await spawnDuplex(
      NODE,
      [
        "-e",
        `process.stdout.write(Buffer.alloc(${String(TWO_MIB)}, 0x61)); process.stderr.write("err");`,
      ],
      { env: ENV, timeoutMs: 20_000 },
    );
    const got = consume(d);
    const r = await d.settled;

    expect(Buffer.concat(got).length).toBe(TWO_MIB);
    expect(r).toMatchObject({ exit_code: 0, stdout: "", truncated: false, stderr: "err" });
  }, 30_000);

  it("the error stream is redacted with a list", async () => {
    const line = `${ALPHA_VALUE} ${BETA_VALUE}\n`;
    const d = await spawnDuplex(NODE, ["-e", `process.stderr.write(${JSON.stringify(line)})`], {
      env: ENV,
      timeoutMs: 10_000,
      redact: [ALPHA_VALUE, BETA_VALUE],
    });
    const r = await d.settled;

    expectAbsent(r.stderr, ALPHA_VALUE);
    expectAbsent(r.stderr, BETA_VALUE);
    expect(r.stderr).toBe("[REDACTED] [REDACTED]\n");
    expect(r.redacted).toBe(true);
  });

  it("a child that closes its input while it is written", async () => {
    const d = await spawnDuplex(
      NODE,
      ["-e", "process.stdin.destroy(); setTimeout(() => process.exit(0), 400)"],
      { env: ENV, timeoutMs: 10_000 },
    );
    const chunk = randomBytes(FOUR_MIB);
    await d.write(chunk);
    expect(isZero(chunk)).toBe(true);
    const r = await d.settled;

    expect(r.exit_code).toBe(0);
    expect(r.spawn_failed).toBe(false);
  });

  it("a write after the child exited resolves at once and zeroes the chunk", async () => {
    const d = await spawnDuplex(NODE, ["-e", "process.exit(3)"], { env: ENV, timeoutMs: 10_000 });
    const r = await d.settled;
    expect(r.exit_code).toBe(3);

    const chunk = Buffer.from("x");
    await d.write(chunk);
    expect(isZero(chunk)).toBe(true);
  });

  it("a child that stops reading, then the abort", async () => {
    const marker = join(dir, "marker");
    const d = await spawnDuplex(
      NODE,
      [
        "-e",
        `require("node:fs").writeFileSync(${JSON.stringify(marker)}, ""); setTimeout(() => {}, 60000);`,
      ],
      { env: ENV, timeoutMs: 30_000 },
    );
    const chunk = randomBytes(FOUR_MIB);
    let written = false;
    const pending = d.write(chunk).then(() => {
      written = true;
    });
    await untilWritten(marker, d.settled, 10_000);
    // A bounded race on the child's own state (testing.md): it never reads.
    await sleep(300);
    expect(written).toBe(false);

    d.abort();
    await pending;
    expect(isZero(chunk)).toBe(true);
    const r = await d.settled;
    expect(r).toMatchObject({ timed_out: true, exit_code: null, signal: "SIGKILL" });
  }, 60_000);

  it("the abort kills the tree as a timeout does", async () => {
    const pidFile = join(dir, "grandchild.pid");
    const d = await spawnDuplex(NODE, ["-e", grandchildScript(pidFile)], {
      env: ENV,
      timeoutMs: 30_000,
    });
    consume(d);
    await untilWritten(pidFile, d.settled, 10_000);
    const pid = Number(readFileSync(pidFile, "utf8"));
    survivor = Number.isInteger(pid) && pid > 0 ? pid : undefined;
    expect(survivor).toBeDefined();

    d.abort();
    const r = await d.settled;
    expect(r.timed_out).toBe(true);
    await expect(untilGone(pid)).resolves.toBe(true);
    survivor = undefined;
  }, 60_000);

  it("the budget", async () => {
    const warm = await spawnDuplex(NODE, ["-e", ""], { env: ENV, timeoutMs: 10_000 });
    await warm.settled;
    const written = join(dir, "written");
    const script = `process.stdout.write("before", () => require("node:fs").writeFileSync(${JSON.stringify(written)}, "")); setTimeout(() => {}, 20000);`;
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const d = await spawnDuplex(NODE, ["-e", script], { env: ENV, timeoutMs: 300 });
    consume(d);
    try {
      await untilWritten(written, d.settled, 10_000);
      await vi.advanceTimersByTimeAsync(300);
      const r = await d.settled;

      expect(r.timed_out).toBe(true);
      expect(r.exit_code).toBeNull();
    } finally {
      await vi.runAllTimersAsync();
      await d.settled;
      vi.useRealTimers();
    }
  }, 60_000);

  it("a consumer that throws ends the child", async () => {
    const d = await spawnDuplex(
      NODE,
      ["-e", 'setInterval(() => process.stdout.write("line\\n"), 50)'],
      { env: ENV, timeoutMs: 10_000 },
    );
    let calls = 0;
    d.onData(() => {
      calls += 1;
      throw new Error("the consumer gives up");
    });
    const r = await d.settled;

    expect(r.timed_out).toBe(true);
    expect(calls).toBe(1);
  }, 30_000);

  it("no chunk after the settle", async () => {
    const go = join(dir, "go");
    const lateWritten = join(dir, "late-written");
    const late = `const fs = require("node:fs"); setTimeout(() => process.exit(0), 20000).unref(); const t = setInterval(() => { if (!fs.existsSync(${JSON.stringify(go)})) return; clearInterval(t); process.stdout.write("late", () => fs.writeFileSync(${JSON.stringify(lateWritten)}, "")); }, 20);`;
    const script = `
      const g = require("node:child_process").spawn(process.execPath, ["-e", ${JSON.stringify(late)}], {
        detached: true,
        stdio: ["ignore", "inherit", "ignore"],
        windowsHide: true,
      });
      g.unref();
      process.stdout.write("early");
    `;
    const d = await spawnDuplex(NODE, ["-e", script], { env: ENV, timeoutMs: 10_000 });
    const got = consume(d);
    const r = await d.settled;
    expect(r.exit_code).toBe(0);

    writeFileSync(go, "");
    await untilWritten(lateWritten, new Promise<never>(() => undefined), 10_000);
    // `late` is in the pipe; its delivery is an absence no product event marks.
    await sleep(250);

    expect(Buffer.concat(got).toString()).toBe("early");
  }, 30_000);

  it("a second consumer is refused", async () => {
    const d = await spawnDuplex(NODE, ["-e", ""], { env: ENV, timeoutMs: 10_000 });
    d.onData(() => undefined);
    expect(() => d.onData(() => undefined)).toThrow("spawnDuplex takes one consumer");
    await d.settled;
  });

  it("end ends the input", async () => {
    const d = await spawnDuplex(NODE, ECHO, { env: ENV, timeoutMs: 10_000 });
    consume(d);
    d.end();
    const r = await d.settled;
    expect(r).toMatchObject({ exit_code: 0, timed_out: false });
  }, 30_000);

  describe("a spawn that fails", () => {
    it.each([
      [
        "a command that does not exist",
        (): [string, string[]] => [join(dir, "does-not-exist"), []],
      ],
      ["the synchronous spawn throw", (): [string, string[]] => [NODE, ["a\u0000b"]]],
    ])("%s", async (_title, target) => {
      const [command, args] = target();
      const d = await spawnDuplex(command, args, { env: ENV, timeoutMs: 10_000 });
      expect(() => d.onData(() => undefined)).not.toThrow();
      const chunk = randomBytes(64);
      await d.write(chunk);
      expect(isZero(chunk)).toBe(true);
      expect(() => d.end()).not.toThrow();
      const r = await d.settled;
      expect(r.spawn_failed).toBe(true);
      expect(() => d.abort()).not.toThrow();
    });
  });

  it("isolation that cannot be delivered rejects before any spawn", async () => {
    forceFsIsolationUnavailableForTests("test");
    await expectVaultError(
      () => spawnDuplex(NODE, ECHO, { env: ENV, timeoutMs: 10_000, fsIsolation: true }),
      ErrorCode.FS_ISOLATION_UNAVAILABLE,
    );
  });

  it("compile-time pin: the duplex takes no stdin buffer", () => {
    const call = (): Promise<DuplexChild> =>
      // @ts-expect-error -- SpawnDuplexOptions has no stdin: the duplex's input is its writes
      spawnDuplex(NODE, [], { env: ENV, timeoutMs: 1, stdin: Buffer.alloc(1) });
    expect(typeof call).toBe("function");
  });
});

describe.skipIf(process.platform === "win32")(
  "through the isolation wrappers (POSIX only: Windows delivers neither isolation, by design)",
  () => {
    let fsAvailable = false;
    let networkAvailable = false;

    beforeAll(async () => {
      let fsProbeError: unknown;
      try {
        await requireFsIsolation("/bin/true", []);
        fsAvailable = true;
      } catch (err) {
        fsProbeError = err;
      }
      if (!fsAvailable && tierRequired("fs-isolation")) {
        throw new Error(
          `HARPOC_REQUIRE_PLATFORM_TESTS demands the "fs-isolation" tier but its probe failed: ${String(fsProbeError)}`,
        );
      }
      let networkProbeError: unknown;
      try {
        await requireNetworkIsolation("/bin/true", []);
        networkAvailable = true;
      } catch (err) {
        networkProbeError = err;
      }
      if (!networkAvailable && tierRequired("isolation")) {
        throw new Error(
          `HARPOC_REQUIRE_PLATFORM_TESTS demands the "isolation" tier but its probe failed: ${String(networkProbeError)}`,
        );
      }
    });

    async function binaryBothWays(isolation: {
      fsIsolation?: boolean;
      networkIsolation?: boolean;
    }): Promise<SpawnCapturedResult> {
      const d = await spawnDuplex(NODE, ECHO, { env: ENV, timeoutMs: 20_000, ...isolation });
      const got = consume(d);
      const writes = binaryWrites();
      const copy = Buffer.concat(writes);
      for (const chunk of writes) await d.write(chunk);
      d.end();
      const r = await d.settled;
      expect(Buffer.concat(got).equals(copy)).toBe(true);
      expect(r).toMatchObject({ exit_code: 0, stdout: "", truncated: false });
      return r;
    }

    it("binary bytes both ways under filesystem isolation", async (ctx) => {
      if (!fsAvailable)
        return ctx.skip("filesystem isolation is unavailable and not required here");
      const r = await binaryBothWays({ fsIsolation: true });
      expect(r.fs_isolation_mechanism).toBeDefined();
    }, 30_000);

    it("binary bytes both ways under network isolation", async (ctx) => {
      if (!networkAvailable) {
        return ctx.skip("network isolation is unavailable and not required here");
      }
      const r = await binaryBothWays({ networkIsolation: true });
      expect(r.isolation_mechanism).toBeDefined();
    }, 30_000);

    it("binary bytes both ways under both isolations", async (ctx) => {
      if (!fsAvailable || !networkAvailable) {
        return ctx.skip("filesystem or network isolation is unavailable and not required here");
      }
      const r = await binaryBothWays({ fsIsolation: true, networkIsolation: true });
      expect(r.fs_isolation_mechanism).toBeDefined();
      expect(r.isolation_mechanism).toBeDefined();
    }, 30_000);
  },
);
