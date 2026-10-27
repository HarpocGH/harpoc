import { afterEach, describe, expect, it, vi } from "vitest";
import { getToken } from "./auth/token-store";

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
    // Let the boot render's scheduled work settle before the file's jsdom is
    // torn down. Under `src/__fixtures__/vitest-setup.ts` Preact hands its
    // after-paint flush to `options.requestAnimationFrame`, a microtask, so the
    // boot render's effects flush right after the render instead of behind a
    // frame. The wait for our own rAF callback and the macrotask after it stays
    // so that the router's `hashchange` effect and the unmount land in order
    // before teardown: on a loaded runner, before the setup, the effect hit
    // `window is not defined` (ubuntu-24, 576f85c) and, once the effect was
    // dropped by unmounting, the fallback timer's own `cancelAnimationFrame`
    // hit a torn-down global (windows-22, 08f74be). Then unmount.
    await new Promise<void>((resolve) => {
      requestAnimationFrame(() => setTimeout(resolve, 0));
    });
    const { render } = await import("preact");
    render(null, document.getElementById("root") as HTMLElement);
  });

  it("adopts the launch token from the fragment and scrubs it during module boot", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    window.location.hash = "#token=a.b.c";
    vi.resetModules();
    await import("./main");
    await new Promise<void>((resolve) => {
      requestAnimationFrame(() => setTimeout(resolve, 0));
    });
    const { render } = await import("preact");
    render(null, document.getElementById("root") as HTMLElement);
    expect(getToken()).toBe("a.b.c");
    expect(window.location.hash).toBe("");
  });
});
