import { cleanup, getConfig, render, screen } from "@testing-library/preact";
import { useEffect, useState } from "preact/hooks";
import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("the suite's scheduling environment (vitest-setup.ts)", () => {
  it("flushes a passive effect queued by a re-render outside act as a microtask, never through a frame", async () => {
    const raf = vi.spyOn(window, "requestAnimationFrame");
    const seen: number[] = [];
    let release: (n: number) => void = () => {};
    const loaded = new Promise<number>((resolve) => {
      release = resolve;
    });
    function Probe() {
      const [n, setN] = useState(0);
      useEffect(() => {
        void loaded.then(setN);
      }, []);
      useEffect(() => {
        if (n !== 0) seen.push(n);
      }, [n]);
      return <span>{n}</span>;
    }
    render(<Probe />);
    raf.mockClear();
    release(7);
    await screen.findByText("7");
    expect(seen).toEqual([7]);
    expect(raf).not.toHaveBeenCalled();
  });

  it("gives every async query and waitFor a 4 s budget", () => {
    expect(getConfig().asyncUtilTimeout).toBe(4000);
  });

  it("runs an unmounted tree's passive cleanup before the next macrotask (preact 11 defers it to the after-paint flush)", async () => {
    const flags: string[] = [];
    function Probe() {
      useEffect(
        () => () => {
          flags.push("cleaned");
        },
        [],
      );
      return <i />;
    }
    render(<Probe />);
    cleanup();
    await Promise.resolve();
    expect(flags).toEqual(["cleaned"]);
  });
});
