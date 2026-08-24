import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  sessionStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  document.body.innerHTML = "";
});

describe("main boot", () => {
  it("applies the stored theme before the first render", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    sessionStorage.setItem("harpoc.theme", "dark");
    vi.resetModules();
    await import("./main");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });
});
