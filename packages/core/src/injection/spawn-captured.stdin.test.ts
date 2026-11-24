import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ErrorCode } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import {
  STDIN_ECHO_SCRIPT,
  STDIN_OPEN_PIPE_SCRIPT,
  untilWritten,
} from "./__fixtures__/spawn-children.js";
import { forceFsIsolationUnavailableForTests, requireFsIsolation } from "./fs-isolation.js";
import { requireNetworkIsolation } from "./network-isolation.js";
import { spawnCaptured } from "./spawn-captured.js";

const ENV: Record<string, string> = {
  PATH: process.env.PATH ?? process.env.Path ?? "",
  ...(process.platform === "win32" && process.env.SystemRoot
    ? { SystemRoot: process.env.SystemRoot }
    : {}),
};
const SECRET_LINE = "secret-line";

const NODE = process.execPath;
const FOUR_MIB = 4 * 1024 * 1024;
const LINES = "first line\nsecond line\nthird line\n";
const ECHO = ["-e", STDIN_ECHO_SCRIPT];
const DIGEST = [
  "-e",
  'const h = require("node:crypto").createHash("sha256"); process.stdin.on("data", (c) => h.update(c)); process.stdin.on("end", () => process.stdout.write(h.digest("hex")));',
];
const OPEN_PIPE = ["-e", STDIN_OPEN_PIPE_SCRIPT];

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-spawn-stdin-"));
});

afterEach(() => {
  vi.useRealTimers();
  forceFsIsolationUnavailableForTests(null);
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("spawnCaptured — the standard input seam", () => {
  it("a child that echoes its input gets the buffer and the end of it", async () => {
    const input = Buffer.from(LINES);
    const r = await spawnCaptured(NODE, ECHO, { env: ENV, timeoutMs: 10_000, stdin: input });
    expect(r.stdout).toBe(LINES);
    expect(r.exit_code).toBe(0);
    expect(input.every((b) => b === 0)).toBe(true);
  });

  it("4 MiB arrive whole", async () => {
    const input = randomBytes(FOUR_MIB);
    const digest = createHash("sha256").update(input).digest("hex");
    const r = await spawnCaptured(NODE, DIGEST, { env: ENV, timeoutMs: 20_000, stdin: input });
    expect(r.stdout).toBe(digest);
    expect(r.exit_code).toBe(0);
    expect(input.every((b) => b === 0)).toBe(true);
  });

  it("a child that closes its input at once", async () => {
    const input = randomBytes(FOUR_MIB);
    const r = await spawnCaptured(
      NODE,
      ["-e", "process.stdin.destroy(); setTimeout(() => process.exit(0), 400)"],
      { env: ENV, timeoutMs: 10_000, stdin: input },
    );
    expect(r.exit_code).toBe(0);
    expect(r.spawn_failed).toBe(false);
    expect(input.every((b) => b === 0)).toBe(true);
  });

  it("a child that exits without reading", async () => {
    const input = randomBytes(FOUR_MIB);
    const r = await spawnCaptured(NODE, ["-e", "process.exit(3)"], {
      env: ENV,
      timeoutMs: 10_000,
      stdin: input,
    });
    expect(r.exit_code).toBe(3);
    expect(input.every((b) => b === 0)).toBe(true);
  });

  it("a child that never reads is killed at its budget", async () => {
    await spawnCaptured(NODE, ["-e", ""], { env: ENV, timeoutMs: 10_000 });
    const written = join(dir, "written");
    const script = `process.stdout.write("before", () => require("node:fs").writeFileSync(${JSON.stringify(written)}, "")); setTimeout(() => {}, 20000);`;
    const input = randomBytes(FOUR_MIB);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const pending = spawnCaptured(NODE, ["-e", script], {
      env: ENV,
      timeoutMs: 300,
      stdin: input,
    });
    try {
      await untilWritten(written, pending, 10_000);
      await vi.advanceTimersByTimeAsync(300);
      const r = await pending;

      expect(r.timed_out).toBe(true);
      expect(r.exit_code).toBeNull();
      expect(input.every((b) => b === 0)).toBe(true);
    } finally {
      await vi.runAllTimersAsync();
      await pending;
      vi.useRealTimers();
    }
  }, 60_000);

  describe("a spawn that fails", () => {
    it("a command that does not exist", async () => {
      const input = randomBytes(FOUR_MIB);
      const r = await spawnCaptured(join(dir, "does-not-exist"), [], {
        env: ENV,
        timeoutMs: 10_000,
        stdin: input,
      });
      expect(r.spawn_failed).toBe(true);
      expect(input.every((b) => b === 0)).toBe(true);
    });

    it("the synchronous spawn throw", async () => {
      const input = randomBytes(FOUR_MIB);
      const r = await spawnCaptured(NODE, ["a\u0000b"], {
        env: ENV,
        timeoutMs: 1_000,
        stdin: input,
      });
      expect(r.spawn_failed).toBe(true);
      expect(input.every((b) => b === 0)).toBe(true);
    });
  });

  it("isolation that cannot be delivered", async () => {
    forceFsIsolationUnavailableForTests("test");
    const input = randomBytes(FOUR_MIB);
    await expectVaultError(
      () =>
        spawnCaptured(NODE, ECHO, {
          env: ENV,
          timeoutMs: 10_000,
          fsIsolation: true,
          stdin: input,
        }),
      ErrorCode.FS_ISOLATION_UNAVAILABLE,
    );
    expect(input.every((b) => b === 0)).toBe(true);
  });

  describe("the redaction is the caller's list", () => {
    it("redacts what the caller names", async () => {
      const r = await spawnCaptured(NODE, ECHO, {
        env: ENV,
        timeoutMs: 10_000,
        stdin: Buffer.from(`frame\n${SECRET_LINE}\n`),
        redact: [SECRET_LINE],
      });
      expectAbsent(r.stdout, SECRET_LINE);
      expect(r.stdout).toBe("frame\n[REDACTED]\n");
      expect(r.redacted).toBe(true);
      expect(r.exit_code).toBe(0);
    });

    it("without redact the same buffer comes back whole", async () => {
      const r = await spawnCaptured(NODE, ECHO, {
        env: ENV,
        timeoutMs: 10_000,
        stdin: Buffer.from(`frame\n${SECRET_LINE}\n`),
      });
      expect(r.stdout).toBe(`frame\n${SECRET_LINE}\n`);
      expect(r.redacted).toBe(false);
      expect(r.exit_code).toBe(0);
    });
  });

  it("without a buffer the child's standard input is an open pipe, never written and never ended", async () => {
    const r = await spawnCaptured(NODE, OPEN_PIPE, { env: ENV, timeoutMs: 10_000 });
    expect(r.stdout).toBe("open");
    expect(r.exit_code).toBe(0);
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

    it("the echo child under filesystem isolation", async (ctx) => {
      if (!fsAvailable)
        return ctx.skip("filesystem isolation is unavailable and not required here");
      const input = Buffer.from(LINES);
      const r = await spawnCaptured(NODE, ECHO, {
        env: ENV,
        timeoutMs: 10_000,
        fsIsolation: true,
        stdin: input,
      });
      expect(r.stdout).toBe(LINES);
      expect(r.exit_code).toBe(0);
      expect(r.fs_isolation_mechanism).toBeDefined();
      expect(input.every((b) => b === 0)).toBe(true);
    });

    it("the echo child under network isolation", async (ctx) => {
      if (!networkAvailable) {
        return ctx.skip("network isolation is unavailable and not required here");
      }
      const input = Buffer.from(LINES);
      const r = await spawnCaptured(NODE, ECHO, {
        env: ENV,
        timeoutMs: 10_000,
        networkIsolation: true,
        stdin: input,
      });
      expect(r.stdout).toBe(LINES);
      expect(r.exit_code).toBe(0);
      expect(r.isolation_mechanism).toBeDefined();
      expect(input.every((b) => b === 0)).toBe(true);
    });

    it("the echo child under both isolations", async (ctx) => {
      if (!fsAvailable || !networkAvailable) {
        return ctx.skip("filesystem or network isolation is unavailable and not required here");
      }
      const input = Buffer.from(LINES);
      const r = await spawnCaptured(NODE, ECHO, {
        env: ENV,
        timeoutMs: 10_000,
        fsIsolation: true,
        networkIsolation: true,
        stdin: input,
      });
      expect(r.stdout).toBe(LINES);
      expect(r.exit_code).toBe(0);
      expect(r.fs_isolation_mechanism).toBeDefined();
      expect(r.isolation_mechanism).toBeDefined();
      expect(input.every((b) => b === 0)).toBe(true);
    });
  },
);
