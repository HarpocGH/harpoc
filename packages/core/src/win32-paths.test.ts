import { afterEach, describe, expect, it } from "vitest";
import { system32Path } from "./win32-paths.js";

// The variable is restored by hand rather than through vi.stubEnv: an unset
// value must round-trip as "unset", not as the string "undefined".
const saved = process.env["SystemRoot"];
afterEach(() => {
  if (saved === undefined) delete process.env["SystemRoot"];
  else process.env["SystemRoot"] = saved;
});

describe("system32Path", () => {
  it("builds the path under the session's SystemRoot", () => {
    process.env["SystemRoot"] = "D:\\Win";
    expect(system32Path("taskkill.exe")).toMatch(/^D:\\Win[\\/]System32[\\/]taskkill\.exe$/);
  });

  it("joins every segment under System32", () => {
    process.env["SystemRoot"] = "D:\\Win";
    expect(system32Path("WindowsPowerShell", "v1.0", "powershell.exe")).toMatch(
      /^D:\\Win[\\/]System32[\\/]WindowsPowerShell[\\/]v1\.0[\\/]powershell\.exe$/,
    );
  });

  it("names System32 itself with no segments", () => {
    process.env["SystemRoot"] = "D:\\Win";
    expect(system32Path()).toMatch(/^D:\\Win[\\/]System32$/);
  });

  it("falls back to C:\\Windows when SystemRoot is unset", () => {
    delete process.env["SystemRoot"];
    expect(system32Path("icacls.exe")).toMatch(/^C:\\Windows[\\/]System32[\\/]icacls\.exe$/);
  });
});
