import { join, parse, sep } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { resolveSpelledDirectory } from "./local-path.js";

const ROOT = parse(process.cwd()).root;
const AGENT = join(ROOT, "agent");
const AGENT_RESOLVED = join(ROOT, "resolved", "agent");
const SPELLED = join(AGENT, "link");
const BEHIND_A_FILE = [AGENT, "file", ".."].join(sep);

const NOT_THERE = ["ENOENT", "ENOTDIR"] as const;
const NOT_READ = ["ENAMETOOLONG", "EACCES", "ELOOP", "EIO"] as const;

function failure(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`${code}: scripted`), { code });
}

/**
 * A file system in which the caller's directory resolves, to a path that
 * resolves to itself, and the step behind it answers as scripted: `realpath`
 * and `lstat` each fail with the code given, and `lstat` answers where its
 * code is null.
 */
function scripted(step: { realpath: string; lstat: string | null }) {
  return {
    realpath: vi.fn(async (path: string): Promise<string> => {
      if (path === AGENT || path === AGENT_RESOLVED) return AGENT_RESOLVED;
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
      const answer = join(AGENT_RESOLVED, "link");
      expect(await resolveSpelledDirectory(SPELLED, fs)).toBe(answer);
      expect(fs.realpath.mock.calls).toEqual([[SPELLED], [AGENT], [answer], [AGENT_RESOLVED]]);
      expect(fs.lstat.mock.calls).toEqual([[SPELLED], [answer]]);
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

type Answer<T> = { is: T } | { fails: string };

/** A file system from two tables; a path neither names fails with `ENOENT`. */
function tabled(table: {
  realpath: Record<string, Answer<string>>;
  lstat: Record<string, Answer<true>>;
}) {
  const ask = <T>(answers: Record<string, Answer<T>>, path: string): T => {
    const answer = answers[path] ?? { fails: "ENOENT" };
    if ("fails" in answer) throw failure(answer.fails);
    return answer.is;
  };
  return {
    realpath: vi.fn(async (path: string): Promise<string> => ask(table.realpath, path)),
    lstat: vi.fn(async (path: string): Promise<unknown> => ask(table.lstat, path)),
  };
}

describe("resolveSpelledDirectory: the answer is resolved once more and must be itself", () => {
  it("an answer that resolves as a whole to itself is handed on", async () => {
    const fs = tabled({
      realpath: { [SPELLED]: { is: AGENT_RESOLVED }, [AGENT_RESOLVED]: { is: AGENT_RESOLVED } },
      lstat: {},
    });
    expect(await resolveSpelledDirectory(SPELLED, fs)).toBe(AGENT_RESOLVED);
    expect(fs.realpath.mock.calls).toEqual([[SPELLED], [AGENT_RESOLVED]]);
  });

  it("an answer whose head resolves to another path the second time is null", async () => {
    const fs = tabled({
      realpath: {
        [AGENT]: { is: AGENT_RESOLVED },
        [AGENT_RESOLVED]: { is: join(ROOT, "moved", "agent") },
      },
      lstat: {},
    });
    expect(await resolveSpelledDirectory(SPELLED, fs)).toBeNull();
  });

  // Darwin's realpath takes a `..` off the name of a file; its kernel, like Linux's kernel and
  // realpath, answers ENOTDIR for the same spelling. The tables script that disagreement.
  it("where realpath takes a `..` off a file's name and lstat refuses the spelling, a link that leads nowhere behind it is null", async () => {
    const spelled = [BEHIND_A_FILE, "dead"].join(sep);
    const answer = join(AGENT_RESOLVED, "dead");
    const fs = tabled({
      realpath: {
        [BEHIND_A_FILE]: { is: AGENT_RESOLVED },
        [AGENT_RESOLVED]: { is: AGENT_RESOLVED },
      },
      lstat: { [spelled]: { fails: "ENOTDIR" }, [answer]: { is: true } },
    });
    expect(await resolveSpelledDirectory(spelled, fs)).toBeNull();
    expect(fs.realpath.mock.calls).toEqual([[spelled], [BEHIND_A_FILE], [answer]]);
    expect(fs.lstat.mock.calls).toEqual([[spelled], [answer]]);
  });

  it("where realpath takes a `..` off a file's name and lstat refuses the spelling, a name that is not there behind it is joined to the file's directory", async () => {
    const spelled = [BEHIND_A_FILE, "clone"].join(sep);
    const fs = tabled({
      realpath: {
        [BEHIND_A_FILE]: { is: AGENT_RESOLVED },
        [AGENT_RESOLVED]: { is: AGENT_RESOLVED },
      },
      lstat: { [spelled]: { fails: "ENOTDIR" } },
    });
    expect(await resolveSpelledDirectory(spelled, fs)).toBe(join(AGENT_RESOLVED, "clone"));
  });

  it.each(["ENAMETOOLONG", "EACCES", "ELOOP", "EIO"])(
    "an answer the system answers %s for the second time is null",
    async (code) => {
      const answer = join(AGENT_RESOLVED, "link");
      const fs = tabled({
        realpath: { [AGENT]: { is: AGENT_RESOLVED }, [AGENT_RESOLVED]: { is: AGENT_RESOLVED } },
        lstat: { [answer]: { fails: code } },
      });
      expect(await resolveSpelledDirectory(SPELLED, fs)).toBeNull();
    },
  );
});
