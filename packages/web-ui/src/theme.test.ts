import { afterEach, describe, expect, it, vi } from "vitest";
import { applyTheme, cycleTheme, setTheme, storedTheme } from "./theme";

afterEach(() => {
  sessionStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  vi.restoreAllMocks();
});

describe("theme", () => {
  it("defaults to system (null) with nothing stored", () => {
    expect(storedTheme()).toBeNull();
  });

  it("setTheme persists to sessionStorage under harpoc.theme and stamps data-theme", () => {
    setTheme("light");
    expect(sessionStorage.getItem("harpoc.theme")).toBe("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });

  it("setTheme(null) clears both the key and the attribute", () => {
    setTheme("dark");
    setTheme(null);
    expect(sessionStorage.getItem("harpoc.theme")).toBeNull();
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("ignores a garbage stored value", () => {
    sessionStorage.setItem("harpoc.theme", "mauve");
    expect(storedTheme()).toBeNull();
  });

  it("cycles system → light → dark → system", () => {
    expect(cycleTheme()).toBe("light");
    expect(cycleTheme()).toBe("dark");
    expect(cycleTheme()).toBeNull();
  });

  it("applyTheme alone never writes storage", () => {
    applyTheme("dark");
    expect(sessionStorage.getItem("harpoc.theme")).toBeNull();
  });

  it("keeps cycling when sessionStorage refuses the write", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("refused");
    });
    expect(cycleTheme()).toBe("light");
    expect(cycleTheme()).toBe("dark");
    expect(cycleTheme()).toBeNull();
    expect(sessionStorage.getItem("harpoc.theme")).toBeNull();
  });
});
