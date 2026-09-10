import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  JOB_WRAPPER_COMPILE_TIMEOUT_MS,
  JOB_WRAPPER_KEEP_FLAG,
  JOB_WRAPPER_PROBE_TIMEOUT_MS,
  JOB_WRAPPER_RETRY_MS,
  JOB_WRAPPER_SOURCE,
  JOB_WRAPPER_SOURCE_SHA256,
  forceJobWrapperUnavailableForTests,
  isJobWrapperFailure,
  jobWrapperCacheDirs,
  jobWrapperCompilerCandidates,
  jobWrapperExePath,
  resetJobWrapperProbeForTests,
  resolveJobWrapper,
  wrapInJob,
} from "./win32-job-wrapper.js";
import type { JobWrapperSeams } from "./win32-job-wrapper.js";

const TRICKY = [
  "a b",
  'c"d',
  "e\\f",
  'g\\"h',
  "",
  "i\\\\",
  '"',
  " j ",
  "k=l m",
  "tab\there",
  '\\\\"\\',
  "end\\",
  "trail\\\\ ",
];

let dir: string;
const calls: Array<{ command: string; args: string[]; timeoutMs: number }> = [];

/** A csc stand-in that writes the requested -out: file; a probe stand-in that exits 0. */
function fakeHelper(cscExit = 0, probeExit = 0): JobWrapperSeams["runHelper"] {
  return (command, args, timeoutMs) => {
    calls.push({ command, args, timeoutMs });
    if (command.endsWith("csc.exe")) {
      const out = args.find((a) => a.startsWith("-out:"))?.slice(5);
      if (cscExit === 0 && out) writeFileSync(out, "MZ-fake");
      return Promise.resolve({ code: cscExit });
    }
    return Promise.resolve({ code: probeExit });
  };
}

function seams(overrides: Partial<JobWrapperSeams> = {}): JobWrapperSeams {
  return {
    platform: "win32",
    compilerCandidates: [join(dir, "no-csc.exe"), join(dir, "csc.exe")],
    cacheDirs: [join(dir, "dist-win32"), join(dir, "home-helpers")],
    probeBinary: (p) => existsSync(p),
    runHelper: fakeHelper(),
    restrictDir: () => undefined,
    ...overrides,
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-job-wrapper-"));
  writeFileSync(join(dir, "csc.exe"), "");
  calls.length = 0;
  resetJobWrapperProbeForTests();
  forceJobWrapperUnavailableForTests(null);
});

afterEach(() => {
  vi.useRealTimers();
  resetJobWrapperProbeForTests();
  forceJobWrapperUnavailableForTests(null);
  rmSync(dir, { recursive: true, force: true });
});

describe("the source and its paths", () => {
  it("hashes the source and names the exe by the hash's first sixteen hex digits", () => {
    expect(JOB_WRAPPER_SOURCE_SHA256).toMatch(/^[0-9a-f]{64}$/);
    expect(jobWrapperExePath("C:\\cache")).toBe(
      join("C:\\cache", "harpoc-job", JOB_WRAPPER_SOURCE_SHA256.slice(0, 16), "harpoc-job.exe"),
    );
  });

  it("keeps the wrapper C# 5 and silent: no interpolation, no environment read, one failure prefix", () => {
    expect(JOB_WRAPPER_SOURCE).not.toMatch(/\$"/);
    expect(JOB_WRAPPER_SOURCE).not.toMatch(/nameof\(|out var /);
    expect(JOB_WRAPPER_SOURCE).not.toMatch(/GetEnvironmentVariable|Environment\./);
    expect(JOB_WRAPPER_SOURCE.match(/Console\.Error\.WriteLine\("harpoc-job: /g)).toHaveLength(4);
    expect(JOB_WRAPPER_SOURCE).not.toMatch(/Console\.(Out|Write)/);
  });

  it("pins the compiler under Microsoft.NET and the cache under core's dist then the home helpers", () => {
    expect(jobWrapperCompilerCandidates()).toEqual([
      expect.stringMatching(/[\\/]Microsoft\.NET[\\/]Framework64[\\/]v4\.0\.30319[\\/]csc\.exe$/),
      expect.stringMatching(/[\\/]Microsoft\.NET[\\/]Framework[\\/]v4\.0\.30319[\\/]csc\.exe$/),
    ]);
    const [dist, home] = jobWrapperCacheDirs();
    expect(dist).toMatch(/[\\/]packages[\\/]core[\\/]dist[\\/]win32$/);
    expect(home).toMatch(/[\\/]\.harpoc[\\/]helpers$/);
  });
});

describe("resolveJobWrapper", () => {
  it("is unavailable off win32 without spawning anything", async () => {
    const r = await resolveJobWrapper(seams({ platform: "linux" }));
    expect(r).toEqual({ unavailable: "unsupported platform: linux" });
    expect(calls).toHaveLength(0);
  });

  it("uses an existing exe from the first cache dir and only runs the probe", async () => {
    const exe = jobWrapperExePath(join(dir, "dist-win32"));
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(exe, ".."), { recursive: true });
    writeFileSync(exe, "MZ-existing");
    const r = await resolveJobWrapper(seams());
    expect(r).toEqual({ exe });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      command: exe,
      args: [JOB_WRAPPER_KEEP_FLAG, expect.stringMatching(/cmd\.exe$/), "/c", "exit"],
      timeoutMs: JOB_WRAPPER_PROBE_TIMEOUT_MS,
    });
  });

  it("compiles into the first cache dir when the exe is missing, writing the source beside it", async () => {
    const r = await resolveJobWrapper(seams());
    const exe = jobWrapperExePath(join(dir, "dist-win32"));
    expect(r).toEqual({ exe });
    expect(readFileSync(join(exe, "..", "harpoc-job.cs"), "utf8")).toBe(JOB_WRAPPER_SOURCE);
    expect(calls[0]).toMatchObject({
      command: join(dir, "csc.exe"),
      args: [
        "-nologo",
        "-optimize",
        "-target:exe",
        "-platform:anycpu",
        expect.stringMatching(/^-out:.*harpoc-job\.\d+\.tmp\.exe$/),
        join(exe, "..", "harpoc-job.cs"),
      ],
      timeoutMs: JOB_WRAPPER_COMPILE_TIMEOUT_MS,
    });
    expect(existsSync(exe)).toBe(true);
  });

  it("falls through to the home helpers dir, restricted to the owner, when the first dir is not writable", async () => {
    writeFileSync(join(dir, "dist-win32"), "a file where the dir should be");
    const restricted: string[] = [];
    const r = await resolveJobWrapper(seams({ restrictDir: (d) => restricted.push(d) }));
    expect(r).toEqual({ exe: jobWrapperExePath(join(dir, "home-helpers")) });
    expect(restricted).toEqual([join(dir, "home-helpers")]);
  });

  it("is unavailable when the owner restriction fails, and compiles nothing into that dir", async () => {
    writeFileSync(join(dir, "dist-win32"), "a file where the dir should be");
    const r = await resolveJobWrapper(
      seams({
        restrictDir: () => {
          throw new Error("icacls exited 5");
        },
      }),
    );
    expect(r).toEqual({ unavailable: expect.stringMatching(/icacls exited 5/) });
    expect(existsSync(jobWrapperExePath(join(dir, "home-helpers")))).toBe(false);
  });

  it("is unavailable when no compiler candidate exists", async () => {
    const r = await resolveJobWrapper(seams({ compilerCandidates: [join(dir, "nope.exe")] }));
    expect(r).toEqual({ unavailable: expect.stringMatching(/^csc\.exe not found/) });
    expect(calls).toHaveLength(0);
  });

  it("is unavailable when the compile fails, and when the probe run does not exit 0", async () => {
    expect(await resolveJobWrapper(seams({ runHelper: fakeHelper(1) }))).toEqual({
      unavailable: expect.stringMatching(/^compile failed: csc exited 1/),
    });
    resetJobWrapperProbeForTests();
    expect(await resolveJobWrapper(seams({ runHelper: fakeHelper(0, 9010) }))).toEqual({
      unavailable: "probe run exited 9010",
    });
  });

  it("caches a success for the process and holds an unavailable verdict for JOB_WRAPPER_RETRY_MS", async () => {
    let now = 1_000_000;
    const s = seams({ runHelper: fakeHelper(0, 1), now: () => now });
    expect(await resolveJobWrapper(s)).toEqual({ unavailable: "probe run exited 1" });
    expect(await resolveJobWrapper(s)).toEqual({ unavailable: "probe run exited 1" });
    expect(calls.filter((c) => c.command.endsWith("csc.exe"))).toHaveLength(1);
    now += JOB_WRAPPER_RETRY_MS + 1;
    const ok = seams({ runHelper: fakeHelper(0, 0), now: () => now });
    expect(await resolveJobWrapper(ok)).toEqual({
      exe: jobWrapperExePath(join(dir, "dist-win32")),
    });
    const before = calls.length;
    expect(await resolveJobWrapper(ok)).toEqual({
      exe: jobWrapperExePath(join(dir, "dist-win32")),
    });
    expect(calls.length).toBe(before);
  });

  it("coalesces concurrent callers on one resolution", async () => {
    const [a, b] = await Promise.all([resolveJobWrapper(seams()), resolveJobWrapper(seams())]);
    expect(a).toEqual(b);
    expect(calls.filter((c) => c.command.endsWith("csc.exe"))).toHaveLength(1);
  });

  it("never rejects: a throwing seam reads as unavailable", async () => {
    const r = await resolveJobWrapper(
      seams({ runHelper: () => Promise.reject(new Error("boom")) }),
    );
    expect(r).toEqual({ unavailable: "compile failed: boom" });
  });

  it("honours the forced-unavailable seam ahead of everything", async () => {
    forceJobWrapperUnavailableForTests("test: fallback tier");
    expect(await resolveJobWrapper(seams())).toEqual({ unavailable: "test: fallback tier" });
    expect(calls).toHaveLength(0);
  });
});

describe("wrapInJob", () => {
  it("prefixes --keep and the payload, args untouched", async () => {
    const wrap = await wrapInJob("C:\\bin\\tool.exe", ["a b", 'c"d', ""], seams());
    expect(wrap).toEqual({
      command: jobWrapperExePath(join(dir, "dist-win32")),
      args: [JOB_WRAPPER_KEEP_FLAG, "C:\\bin\\tool.exe", "a b", 'c"d', ""],
      mechanism: "job",
    });
  });

  it("returns null when unavailable", async () => {
    expect(await wrapInJob("x", [], seams({ platform: "darwin" }))).toBeNull();
  });
});

describe("isJobWrapperFailure", () => {
  it("is the reserved exit code plus the marker, never one alone", () => {
    expect(isJobWrapperFailure(9009, "harpoc-job: CreateProcess failed: 3\r\n")).toBe(true);
    expect(isJobWrapperFailure(9010, "harpoc-job: job object failed: 5")).toBe(true);
    expect(isJobWrapperFailure(9011, "harpoc-job: assign failed: 5")).toBe(true);
    expect(isJobWrapperFailure(9009, "")).toBe(false);
    expect(isJobWrapperFailure(9009, "not the wrapper")).toBe(false);
    expect(isJobWrapperFailure(1, "harpoc-job: CreateProcess failed: 3")).toBe(false);
    expect(isJobWrapperFailure(null, "harpoc-job: x")).toBe(false);
  });
});

describe.runIf(process.platform === "win32")("win32 — the real wrapper", () => {
  it("compiles from the constant into a temp cache, passes its probe, and echoes argv byte-identical", async () => {
    resetJobWrapperProbeForTests();
    const r = await resolveJobWrapper({ cacheDirs: [join(dir, "live")] });
    expect(r).toEqual({ exe: jobWrapperExePath(join(dir, "live")) });
    const wrap = await wrapInJob(
      process.execPath,
      ["-e", "console.log(JSON.stringify(process.argv.slice(1)))", "--", ...TRICKY],
      { cacheDirs: [join(dir, "live")] },
    );
    expect(wrap).not.toBeNull();
    const { spawnSync } = await import("node:child_process");
    const direct = spawnSync(
      process.execPath,
      ["-e", "console.log(JSON.stringify(process.argv.slice(1)))", "--", ...TRICKY],
      { windowsHide: true, encoding: "utf8" },
    );
    const wrapped = spawnSync(
      (wrap as { command: string }).command,
      (wrap as { args: string[] }).args,
      { windowsHide: true, encoding: "utf8" },
    );
    expect(wrapped.status).toBe(0);
    expect(wrapped.stdout).toBe(direct.stdout);
  }, 120_000);

  it("a missing payload is the wrapper's 9009 with the marker", async () => {
    const wrap = await wrapInJob("C:\\harpoc-no-such\\app.exe", ["x"], {
      cacheDirs: [join(dir, "live")],
    });
    const { spawnSync } = await import("node:child_process");
    const res = spawnSync(
      (wrap as { command: string }).command,
      (wrap as { args: string[] }).args,
      { windowsHide: true, encoding: "utf8" },
    );
    expect(res.status).toBe(9009);
    expect(isJobWrapperFailure(res.status, res.stderr)).toBe(true);
  }, 60_000);
});
