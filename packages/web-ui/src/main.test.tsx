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
    // Unmount before the file's jsdom is torn down: the boot render leaves the
    // router's `hashchange` effect queued behind Preact's after-paint timer,
    // and on a loaded runner that timer fired after teardown — an unhandled
    // `window is not defined` from router.ts that failed the whole run (CI
    // ubuntu-24, 576f85c). Unmounting drops the pending effect deterministically.
    const { render } = await import("preact");
    render(null, document.getElementById("root") as HTMLElement);
  });
});
