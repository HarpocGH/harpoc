import { join, parse } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { resolveSpelledDirectory } from "./local-path.js";

const ROOT = parse(process.cwd()).root;
const AGENT = join(ROOT, "agent");
const AGENT_RESOLVED = join(ROOT, "resolved", "agent");
const SPELLED = join(AGENT, "link");

const NOT_THERE = ["ENOENT", "ENOTDIR"] as const;
const NOT_READ = ["ENAMETOOLONG", "EACCES", "ELOOP", "EIO"] as const;

function failure(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`${code}: scripted`), { code });
}

/**
 * A file system in which the caller's directory resolves and the step behind
 * it answers as scripted: `realpath` and `lstat` each fail with the code
 * given, and `lstat` answers where its code is null.
 */
function scripted(step: { realpath: string; lstat: string | null }) {
  return {
    realpath: vi.fn(async (path: string): Promise<string> => {
      if (path === AGENT) return AGENT_RESOLVED;
      if (path === SPELLED) throw failure(step.realpath);
      throw failure("ENOENT");
    }),
    lstat: vi.fn(async (path: string): Promise<unknown> => {
      if (path === AGENT) return {};
      if (path === SPELLED && step.lstat !== null) throw failure(step.lstat);
      if (path === SPELLED) return {};
      throw failure("ENOENT");
    }),
  };
}

describe("resolveSpelledDirectory: which answers of the system count as a step that is not there", () => {
  it.each(NOT_THERE)(
    "a step realpath and lstat both answer %s for is climbed past: the nearest step that resolves, the rest joined on",
    async (code) => {
      const fs = scripted({ realpath: code, lstat: code });
      expect(await resolveSpelledDirectory(SPELLED, fs)).toBe(join(AGENT_RESOLVED, "link"));
      expect(fs.realpath.mock.calls).toEqual([[SPELLED], [AGENT]]);
      expect(fs.lstat.mock.calls).toEqual([[SPELLED]]);
    },
  );

  it.each(NOT_READ)(
    "a step realpath answers %s for is not climbed past: null, and no shorter step is asked",
    async (code) => {
      const fs = scripted({ realpath: code, lstat: "ENOENT" });
      expect(await resolveSpelledDirectory(SPELLED, fs)).toBeNull();
      expect(fs.realpath.mock.calls).toEqual([[SPELLED]]);
      expect(fs.lstat).not.toHaveBeenCalled();
    },
  );

  it.each(NOT_READ)(
    "a step realpath calls missing and lstat answers %s for is not climbed past: null, and no shorter step is asked",
    async (code) => {
      const fs = scripted({ realpath: "ENOENT", lstat: code });
      expect(await resolveSpelledDirectory(SPELLED, fs)).toBeNull();
      expect(fs.realpath.mock.calls).toEqual([[SPELLED]]);
      expect(fs.lstat.mock.calls).toEqual([[SPELLED]]);
    },
  );

  it.each(NOT_THERE)(
    "a step realpath answers %s for and lstat finds — a link that leads nowhere — is null",
    async (code) => {
      const fs = scripted({ realpath: code, lstat: null });
      expect(await resolveSpelledDirectory(SPELLED, fs)).toBeNull();
      expect(fs.realpath.mock.calls).toEqual([[SPELLED]]);
    },
  );

  it("a failure that carries no code is not climbed past", async () => {
    const fs = {
      realpath: vi.fn(async (path: string): Promise<string> => {
        if (path === AGENT) return AGENT_RESOLVED;
        throw new Error("scripted");
      }),
      lstat: vi.fn(async (): Promise<unknown> => {
        throw failure("ENOENT");
      }),
    };
    expect(await resolveSpelledDirectory(SPELLED, fs)).toBeNull();
    expect(fs.realpath.mock.calls).toEqual([[SPELLED]]);
  });
});
