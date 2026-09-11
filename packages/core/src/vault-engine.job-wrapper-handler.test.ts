import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setJobWrapperUnavailableHandler } from "./injection/win32-job-wrapper.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./injection/win32-job-wrapper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/win32-job-wrapper.js")>();
  return {
    ...actual,
    setJobWrapperUnavailableHandler: vi.fn(actual.setJobWrapperUnavailableHandler),
  };
});

const installed = vi.mocked(setJobWrapperUnavailableHandler);
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-engine-handler-"));
  installed.mockClear();
});
afterEach(() => {
  setJobWrapperUnavailableHandler(null);
  rmSync(dir, { recursive: true, force: true });
});

describe("VaultEngine — the job-wrapper warning seam (note 2, 2026-09-10)", () => {
  it("installs onJobWrapperUnavailable at construction, and null when the option is absent", () => {
    const warn = vi.fn();
    new VaultEngine({
      dbPath: join(dir, "a.db"),
      sessionPath: join(dir, "a.session"),
      onJobWrapperUnavailable: warn,
    });
    expect(installed).toHaveBeenLastCalledWith(warn);
    new VaultEngine({ dbPath: join(dir, "b.db"), sessionPath: join(dir, "b.session") });
    expect(installed).toHaveBeenLastCalledWith(null);
  });
});
