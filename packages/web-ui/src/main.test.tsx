import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  sessionStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  document.body.innerHTML = "";
});

describe("main boot", () => {
  it("stamps data-theme from sessionStorage during module boot", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    sessionStorage.setItem("harpoc.theme", "dark");
    vi.resetModules();
    await import("./main");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    // Let Preact's after-paint scheduling settle before the file's jsdom is
    // torn down. The boot render arms `afterNextFrame` — a requestAnimationFrame
    // racing a 100 ms setTimeout — and queues the router's `hashchange` effect
    // behind it; on a loaded runner both outlived this one-test file: the
    // effect hit `window is not defined` (ubuntu-24, 576f85c) and, once the
    // effect was dropped by unmounting, the fallback timer's own
    // `cancelAnimationFrame` hit a torn-down global (windows-22, 08f74be).
    // Preact registered its rAF before ours, so by the time our frame callback
    // and the macrotask after it run, `done` has cleared its timer and the
    // effect flush it queued has already executed. Then unmount.
    await new Promise<void>((resolve) => {
      requestAnimationFrame(() => setTimeout(resolve, 0));
    });
    const { render } = await import("preact");
    render(null, document.getElementById("root") as HTMLElement);
  });
});
