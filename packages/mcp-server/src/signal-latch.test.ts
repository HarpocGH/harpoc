import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { installSignalLatch } from "./signal-latch.js";

// The latch is pinned over a bare EventEmitter, never over `process`: no
// spawn, no real signal, no race, and nothing a test runner's own handlers
// could intercept — the same on win32, where the kernel delivers no SIGTERM.
describe("installSignalLatch (D8)", () => {
  it("remembers the first stop signal until armed, then delivers it at once", () => {
    const source = new EventEmitter();
    const latch = installSignalLatch(source);
    expect(latch.pending()).toBeNull();

    source.emit("SIGTERM");
    source.emit("SIGINT");
    expect(latch.pending()).toBe("SIGTERM");

    const seen: string[] = [];
    latch.arm((trigger) => seen.push(trigger));
    expect(seen).toEqual(["SIGTERM"]);
  });

  it("delivers nothing on arming without a pending signal, and every later signal to the handler", () => {
    const source = new EventEmitter();
    const latch = installSignalLatch(source);
    const seen: string[] = [];

    latch.arm((trigger) => seen.push(trigger));
    expect(seen).toEqual([]);

    source.emit("SIGINT");
    source.emit("SIGTERM");
    expect(seen).toEqual(["SIGINT", "SIGTERM"]);
    expect(latch.pending()).toBeNull();
  });

  it("dispose detaches both listeners", () => {
    const source = new EventEmitter();
    const latch = installSignalLatch(source);
    expect(source.listenerCount("SIGINT") + source.listenerCount("SIGTERM")).toBe(2);

    latch.dispose();

    expect(source.listenerCount("SIGINT") + source.listenerCount("SIGTERM")).toBe(0);
    source.emit("SIGTERM");
    expect(latch.pending()).toBeNull();
  });
});
