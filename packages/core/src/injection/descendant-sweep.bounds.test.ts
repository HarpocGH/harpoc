import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DESCENDANT_SWEEP_TIMEOUT_MS, win32SweepDeps } from "./descendant-sweep.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

const spawnMock = vi.mocked(spawn);

/** A helper process that never produces output and never closes. */
function hangingChild(): ReturnType<typeof spawn> {
  const child = new EventEmitter() as ReturnType<typeof spawn> & { kill: () => boolean };
  Object.assign(child, { pid: 4242, stdout: new EventEmitter(), kill: vi.fn(() => true) });
  return child;
}

/**
 * The helper bound is what the CI evidence moved: on windows-latest under the
 * full parallel gate a PowerShell 5.1 host plus the CIM listing took longer
 * than 10 s on every run since a7ec9fc (locally: ~250 ms), so the live orphan
 * test's own pre-listing timed out and the product sweep on such a host would
 * have silently failed open. Ruled 2026-08-29: helper 20 s, whole sweep 30 s.
 */
describe("descendant sweep bounds (ruled 2026-08-29)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    spawnMock.mockImplementation(() => hangingChild());
  });

  afterEach(() => {
    vi.useRealTimers();
    spawnMock.mockReset();
  });

  it("gives a helper 20 s before it is abandoned as timed out", async () => {
    let settled: "pending" | "rejected" | "resolved" = "pending";
    const listing = win32SweepDeps()
      .listDescendants(1)
      .then(
        () => {
          settled = "resolved";
        },
        () => {
          settled = "rejected";
        },
      );

    await vi.advanceTimersByTimeAsync(19_999);
    expect(settled).toBe("pending");

    await vi.advanceTimersByTimeAsync(1);
    await listing;
    expect(settled).toBe("rejected");
  });

  it("rejects the abandoned helper as timed out and kills it", async () => {
    const listing = win32SweepDeps().listDescendants(1);
    const outcome = listing.then(
      () => "resolved",
      (err: unknown) => (err instanceof Error ? err.message : String(err)),
    );
    await vi.advanceTimersByTimeAsync(20_000);
    await expect(outcome).resolves.toBe("descendant sweep helper timed out");
    const child = spawnMock.mock.results[0]?.value as { kill: ReturnType<typeof vi.fn> };
    expect(child.kill).toHaveBeenCalledTimes(1);
  });

  it("bounds the whole sweep at 30 s", () => {
    expect(DESCENDANT_SWEEP_TIMEOUT_MS).toBe(30_000);
  });
});
