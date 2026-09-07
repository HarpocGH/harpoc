import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { installSignalLatch, REPEAT_EXIT_CODES, repeatStopLine } from "./signal-latch.js";

// The latch is pinned over a bare EventEmitter, never over `process`: no
// spawn, no real signal, no race, and nothing a test runner's own handlers
// could intercept — the same on win32, where the kernel delivers no SIGTERM.
// `onRepeat` is always injected here: the default exits the process.
describe("installSignalLatch (D8)", () => {
  it("remembers the first stop signal until armed, escalates a second one, then delivers the first at once", () => {
    const source = new EventEmitter();
    const onRepeat = vi.fn();
    const latch = installSignalLatch(source, onRepeat);
    expect(latch.pending()).toBeNull();

    source.emit("SIGTERM");
    expect(onRepeat).not.toHaveBeenCalled();
    source.emit("SIGINT");
    expect(latch.pending()).toBe("SIGTERM");
    expect(onRepeat).toHaveBeenCalledTimes(1);
    expect(onRepeat).toHaveBeenCalledWith("SIGINT");

    const seen: string[] = [];
    latch.arm((trigger) => seen.push(trigger));
    expect(seen).toEqual(["SIGTERM"]);
    expect(onRepeat).toHaveBeenCalledTimes(1);
  });

  it("delivers nothing on arming without a pending signal, and every later signal to the handler, never to onRepeat", () => {
    const source = new EventEmitter();
    const onRepeat = vi.fn();
    const latch = installSignalLatch(source, onRepeat);
    const seen: string[] = [];

    latch.arm((trigger) => seen.push(trigger));
    expect(seen).toEqual([]);

    source.emit("SIGINT");
    source.emit("SIGTERM");
    expect(seen).toEqual(["SIGINT", "SIGTERM"]);
    expect(latch.pending()).toBeNull();
    expect(onRepeat).not.toHaveBeenCalled();
  });

  it("dispose detaches both listeners", () => {
    const source = new EventEmitter();
    const onRepeat = vi.fn();
    const latch = installSignalLatch(source, onRepeat);
    expect(source.listenerCount("SIGINT") + source.listenerCount("SIGTERM")).toBe(2);

    latch.dispose();

    expect(source.listenerCount("SIGINT") + source.listenerCount("SIGTERM")).toBe(0);
    source.emit("SIGTERM");
    source.emit("SIGTERM");
    expect(latch.pending()).toBeNull();
    expect(onRepeat).not.toHaveBeenCalled();
  });

  it("the default escalation's codes and line: 128 + signo, one line naming the signal and the code", () => {
    expect(REPEAT_EXIT_CODES).toEqual({ SIGINT: 130, SIGTERM: 143 });
    expect(repeatStopLine("SIGINT")).toBe(
      "harpoc-mcp: a second SIGINT arrived during start-up, stopping now (exit 130)\n",
    );
    expect(repeatStopLine("SIGTERM")).toBe(
      "harpoc-mcp: a second SIGTERM arrived during start-up, stopping now (exit 143)\n",
    );
  });
});
