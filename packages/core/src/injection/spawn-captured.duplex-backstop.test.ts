import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { vaultText } from "@harpoc/shared";
import { spawnDuplex } from "./spawn-captured.js";
import { forceJobWrapperUnavailableForTests } from "./win32-job-wrapper.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

const spawnMock = vi.mocked(spawn);
const NODE = process.execPath;

/**
 * A child that never exits and never closes: `pid` undefined, so the tree kill is the direct
 * `kill` on every tier; its `stdin` by default a `Writable` whose `write` never calls back.
 */
function stuckChild(
  stdin: Writable = new Writable({
    write() {
      // Never calls back.
    },
  }),
): { child: ReturnType<typeof spawn>; kill: Mock<ChildProcess["kill"]> } {
  const kill: Mock<ChildProcess["kill"]> = vi.fn(() => true);
  const child = Object.assign(new EventEmitter(), {
    pid: undefined,
    kill,
    stdout: new EventEmitter(),
    stdin,
  });
  return { child: child as unknown as ReturnType<typeof spawn>, kill };
}

beforeEach(() => {
  // The win32 wrapper's probe would spawn through the mock; the taskkill tier's kill of a
  // pid-less child is the direct kill, as on POSIX.
  forceJobWrapperUnavailableForTests(vaultText`test: a fake child`);
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});

afterEach(() => {
  vi.useRealTimers();
  forceJobWrapperUnavailableForTests(null);
  spawnMock.mockReset();
});

describe("spawnDuplex — the settle's backstop", () => {
  it("a chunk the child never took is zeroed by the settle", async () => {
    const { child } = stuckChild();
    spawnMock.mockImplementation(() => child);
    const d = await spawnDuplex(NODE, [], { env: {}, timeoutMs: 10_000 });
    const chunk = Buffer.alloc(64, 0xab);
    let resolved = false;
    void d.write(chunk).then(() => {
      resolved = true;
    });
    d.abort();
    await vi.advanceTimersByTimeAsync(2_000); // KILL_SETTLE_MS (spawn-captured.ts)
    const r = await d.settled;

    expect(r.timed_out).toBe(true);
    expect(resolved).toBe(true);
    expect(chunk.every((b) => b === 0)).toBe(true);
  });

  it("the abort kills once", async () => {
    const { child, kill } = stuckChild();
    spawnMock.mockImplementation(() => child);
    const d = await spawnDuplex(NODE, [], { env: {}, timeoutMs: 1_000 });
    d.abort();
    d.abort();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(kill).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2_000);
    const r = await d.settled;
    expect(r.timed_out).toBe(true);
  });
});

describe("spawnDuplex — the write's callback", () => {
  it("a chunk is zeroed in its write's callback, never before", async () => {
    let kept: ((error?: Error | null) => void) | undefined;
    const { child } = stuckChild(
      new Writable({
        write(_chunk, _encoding, callback) {
          kept = callback;
        },
      }),
    );
    spawnMock.mockImplementation(() => child);
    const d = await spawnDuplex(NODE, [], { env: {}, timeoutMs: 10_000 });
    const chunk = Buffer.alloc(64, 0xab);
    const copy = Buffer.from(chunk);
    let resolved = false;
    const pending = d.write(chunk).then(() => {
      resolved = true;
    });
    await new Promise<void>((r) => setImmediate(r));
    expect(kept).toBeDefined();
    expect(chunk.equals(copy)).toBe(true);
    expect(resolved).toBe(false);

    (kept as (error?: Error | null) => void)();
    await pending;
    expect(chunk.every((b) => b === 0)).toBe(true);

    d.abort();
    await vi.advanceTimersByTimeAsync(2_000);
    await d.settled;
  });
});
