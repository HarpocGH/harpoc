import { execFileSync, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { sshHardeningArgs } from "./ssh-common.js";
import { system32Path } from "../win32-paths.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

// On Windows the ephemeral agent listens on a named pipe, which only the native
// Win32-OpenSSH client consumes through SSH_AUTH_SOCK; an MSYS build (the
// Git-bundled ssh a Git-Bash PATH resolves first) finds no agent and is refused
// before any spawn (D58). The git injector resolves ssh for GIT_SSH_COMMAND against
// the process PATH, so the native directory has to lead there
// (ssh-live-auth.test.ts pins the same client for the same reason).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");
// Skipped where git (and, for the SSH transport, the native ssh client) does not resolve.
const describeGit = describe.skipIf(GIT === null);
const describeGitSsh = describe.skipIf(GIT === null || SSH === null);

// A leg that exports the ssh-live tier ships git as well (TM-11): where git does not resolve
// on such a leg, this guard fails the file instead of letting the HTTPS, H6 and isolation
// suites below skip silently.
it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

/** Redirect the temp dir os.tmpdir() reads (TEMP/TMP on win32, TMPDIR on POSIX). */
function overrideTempEnv(dir: string): { TMPDIR?: string; TMP?: string; TEMP?: string } {
  const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = dir;
  process.env.TMP = dir;
  process.env.TEMP = dir;
  return saved;
}

function restoreTempEnv(saved: { TMPDIR?: string; TMP?: string; TEMP?: string }): void {
  if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = saved.TMPDIR;
  if (saved.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = saved.TMP;
  if (saved.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = saved.TEMP;
}

/** The sh git would run GIT_SSH_COMMAND through: /bin/sh, or Git-for-Windows'. */
function findRoundtripSh(): string | null {
  if (process.platform !== "win32") return "/bin/sh";
  const candidates = [
    ...(GIT ? [join(dirname(dirname(GIT)), "usr", "bin", "sh.exe")] : []),
    "C:\\Program Files\\Git\\usr\\bin\\sh.exe",
    "C:\\Program Files\\Git\\bin\\sh.exe",
  ];
  return candidates.find((c) => existsSync(c)) ?? null;
}

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const { spawnCaptured: realSpawnCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");

const NULL_GIT_CONFIG = process.platform === "win32" ? "NUL" : "/dev/null";

/** The git subcommand of an argv: the first word that is neither a `-c` pair nor an option. */
function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

/** An empty repository: a relayed pull's or push's working-tree steps run in it for real. */
function initRepo(): string {
  const wd = mkdtempSync(join(tmpdir(), "harpoc-git-wd-"));
  execFileSync(GIT as string, ["init", "-q", wd], {
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG },
  });
  return wd;
}

/** The working-tree probes run for real; the network step and the final pull answer OK_RESULT. */
function relayWithRealProbes(): void {
  vi.mocked(spawnCaptured).mockImplementation((cmd, args, opts) =>
    ["fetch", "push", "pull"].includes(gitSubcommand(args) ?? "")
      ? Promise.resolve(OK_RESULT)
      : realSpawnCaptured(cmd, args, opts),
  );
}

const FORCED = [
  "-c",
  expect.stringMatching(/^core\.hooksPath=.+harpoc-git-hooks-/),
  "-c",
  "credential.helper=",
  "-c",
  "core.fsmonitor=false",
];

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    ...overrides,
  };
}

type SpawnCall = [
  string,
  string[],
  { env: Record<string, string>; cwd?: string; redact?: string[] },
];

// Positive-path assertions on the spawned git command (code review 2026-07-07,
// M13): the credential must reach git via the vault-authored GIT_ASKPASS helper
// through the child environment — never argv — and the SSH transport must carry
// the hardening args in GIT_SSH_COMMAND.
describeGit("GitInjector HTTPS credential handling (git resolvable)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("passes the credential via GIT_ASKPASS env vars, never argv", async () => {
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "https://8.8.8.8/org/repo.git",
    };
    const result = await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({
        command_allowlist: [GIT as string],
        url_allowlist: ["https://8.8.8.8/*"],
      }),
      undefined,
    );

    expect(result.exit_code).toBe(0);
    const calls = spawnMock.mock.calls as SpawnCall[];
    // The clone's two credential-bearing steps (ls-remote, fetch) run in the
    // relay; the third makes the clone from it (F-1).
    expect(calls.map(([, a]) => gitSubcommand(a))).toEqual(["ls-remote", "fetch", "clone"]);
    for (const [command, args, opts] of calls.slice(0, 2)) {
      expect(command).toBe(GIT);
      expect(args.slice(0, 8)).toEqual(["-c", "http.followRedirects=false", ...FORCED]);
      expect(opts.env.GIT_ASKPASS).toBeTruthy();
      expect(opts.env.HARPOC_GIT_USERNAME).toBe("git-user");
      expect(opts.env.HARPOC_GIT_PASSWORD).toBe("s3cret-token-value");
      expect(opts.env.GIT_TERMINAL_PROMPT).toBe("0");
      // Both credential halves are redacted from any captured output.
      expect(opts.redact).toContain("s3cret-token-value");
      expect(opts.redact).toContain("git-user");
    }
    const [, , cloneOpts] = calls[2] as SpawnCall;
    expect(cloneOpts.env.GIT_ASKPASS).toBeUndefined();
    expect(cloneOpts.env.HARPOC_GIT_PASSWORD).toBeUndefined();

    // The credential appears in no argv element of any step in any form.
    expect(
      calls.every(([, a]) =>
        a.every((x) => !x.includes("s3cret-token-value") && !x.includes("git-user")),
      ),
    ).toBe(true);
  });

  it("push: the network step is the forced config, --git-dir of the relay, the operation, the caller's options, `--`, then the repository; the working-tree steps carry no credential (I18, S1)", async () => {
    const wd = initRepo();
    relayWithRealProbes();
    try {
      const result = await injector.executeWithSecret(
        {
          type: "git",
          operation: "push",
          repository: "https://8.8.8.8/org/repo.git",
          args: ["--force-with-lease", "--follow-tags"],
          working_directory: wd,
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({
          command_allowlist: [GIT as string],
          url_allowlist: ["https://8.8.8.8/*"],
        }),
        undefined,
      );

      expect(result.exit_code).toBe(0);
      const calls = spawnMock.mock.calls as SpawnCall[];
      expect(calls.map(([, a]) => gitSubcommand(a))).toEqual([
        "rev-parse",
        "symbolic-ref",
        "for-each-ref",
        "push",
      ]);
      const [command, args, opts] = calls[3] as SpawnCall;
      expect(command).toBe(GIT);
      expect(args).toEqual([
        "-c",
        "http.followRedirects=false",
        ...FORCED,
        expect.stringMatching(/^--git-dir=.+harpoc-git-relay-/),
        "push",
        "--force-with-lease",
        "--follow-tags",
        "--",
        "https://8.8.8.8/org/repo.git",
      ]);
      expect(opts.cwd).toBe((args[8] as string).slice("--git-dir=".length));
      expect(opts.env.GIT_ASKPASS).toBeTruthy();
      expect(opts.env.HARPOC_GIT_ORIGIN).toBe("https://8.8.8.8");
      for (const [, local, localOpts] of calls.slice(0, 3)) {
        expect(local.slice(0, 6)).toEqual(FORCED);
        expect(localOpts.cwd).toBe(wd);
        expect(localOpts.env.GIT_ASKPASS).toBeUndefined();
        expect(localOpts.env.HARPOC_GIT_PASSWORD).toBeUndefined();
        expect(localOpts.env.HARPOC_GIT_USERNAME).toBeUndefined();
      }
      expect(
        calls.every(([, a]) =>
          a.every((x) => !x.includes("s3cret-token-value") && !x.includes("git-user")),
        ),
      ).toBe(true);
    } finally {
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  // T14: the child environment is built, not inherited (§4.5.3 layer 3). Both
  // git transports were unpinned here, so `{ ...process.env }` in either
  // initializer would have handed the vault process's whole environment —
  // proxy settings, operator-exported tokens, GIT_* overrides — to git.
  it("hands git a built environment, not the vault's own", async () => {
    process.env.HARPOC_T14_GIT_AMBIENT = "ambient-value";
    process.env.HARPOC_T14_GIT_ALLOWED = "allowed-value";
    try {
      await injector.executeWithSecret(
        { type: "git", operation: "clone", repository: "https://8.8.8.8/org/repo.git" },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({
          command_allowlist: [GIT as string],
          url_allowlist: ["https://8.8.8.8/*"],
          env_allowlist: ["HARPOC_T14_GIT_ALLOWED"],
        }),
        undefined,
      );

      const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
      expect(opts.env.HARPOC_T14_GIT_AMBIENT).toBeUndefined();
      expect(opts.env.HARPOC_T14_GIT_ALLOWED).toBe("allowed-value");

      const expected = new Set([
        "PATH",
        "SystemRoot",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_ASKPASS",
        "GIT_TERMINAL_PROMPT",
        "HARPOC_GIT_USERNAME",
        "HARPOC_GIT_PASSWORD",
        "HARPOC_GIT_ORIGIN",
        "HARPOC_T14_GIT_ALLOWED",
      ]);
      expect(Object.keys(opts.env).filter((k) => !expected.has(k))).toEqual([]);
    } finally {
      delete process.env.HARPOC_T14_GIT_AMBIENT;
      delete process.env.HARPOC_T14_GIT_ALLOWED;
    }
  });

  it("S1: no git run reads a system or global config, and an allowlist entry cannot reintroduce either", async () => {
    const saved = {
      nosystem: process.env.GIT_CONFIG_NOSYSTEM,
      global: process.env.GIT_CONFIG_GLOBAL,
    };
    process.env.GIT_CONFIG_NOSYSTEM = "0";
    process.env.GIT_CONFIG_GLOBAL = join(tmpdir(), "harpoc-ambient.gitconfig");
    const wd = initRepo();
    relayWithRealProbes();
    try {
      await injector.executeWithSecret(
        {
          type: "git",
          operation: "pull",
          repository: "https://8.8.8.8/org/repo.git",
          working_directory: wd,
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({
          command_allowlist: [GIT as string],
          url_allowlist: ["https://8.8.8.8/*"],
          env_allowlist: ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"],
        }),
        undefined,
      );
      const calls = spawnMock.mock.calls as SpawnCall[];
      expect(calls.length).toBeGreaterThan(1);
      for (const [, , opts] of calls) {
        expect(opts.env.GIT_CONFIG_NOSYSTEM).toBe("1");
        expect(opts.env.GIT_CONFIG_GLOBAL).toBe(NULL_GIT_CONFIG);
      }
    } finally {
      if (saved.nosystem === undefined) delete process.env.GIT_CONFIG_NOSYSTEM;
      else process.env.GIT_CONFIG_NOSYSTEM = saved.nosystem;
      if (saved.global === undefined) delete process.env.GIT_CONFIG_GLOBAL;
      else process.env.GIT_CONFIG_GLOBAL = saved.global;
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("S5: the clone repository rides behind `--`, after every caller argument", async () => {
    const dest = join(tmpdir(), "harpoc-s5-dest");
    await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: "https://8.8.8.8/org/repo.git",
        args: ["--depth", "1", "https://8.8.8.8/org/other.git"],
        working_directory: dest,
      },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
    );
    const calls = spawnMock.mock.calls as SpawnCall[];
    // The local clone takes the caller's arguments, then `--`, the repository, the destination.
    const [, args] = calls[2] as SpawnCall;
    expect(args.slice(args.indexOf("clone"))).toEqual([
      "clone",
      "--depth",
      "1",
      "https://8.8.8.8/org/other.git",
      "--",
      "https://8.8.8.8/org/repo.git",
      dest,
    ]);
    // The credential-bearing steps name the repository behind `--` and no caller positional.
    for (const [, network] of calls.slice(0, 2)) {
      expect(network[network.indexOf("--") + 1]).toBe("https://8.8.8.8/org/repo.git");
      expect(network).not.toContain("https://8.8.8.8/org/other.git");
    }
  });

  it("S1: a clone's credential-bearing steps — ls-remote, then fetch — run in the relay, never the destination; the clone itself runs from the relay without the credential (F-1)", async () => {
    const dest = join(tmpdir(), "harpoc-f1-dest");
    const result = await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: "https://8.8.8.8/org/repo.git",
        args: ["--depth", "1", "--branch", "main"],
        working_directory: dest,
      },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
    );

    expect(result.exit_code).toBe(0);
    const calls = spawnMock.mock.calls as SpawnCall[];
    expect(calls.map(([, a]) => gitSubcommand(a))).toEqual(["ls-remote", "fetch", "clone"]);
    const [, lsArgs, lsOpts] = calls[0] as SpawnCall;
    const [, fetchArgs, fetchOpts] = calls[1] as SpawnCall;
    const [, cloneArgs, cloneOpts] = calls[2] as SpawnCall;
    const relay = (fetchArgs[8] as string).slice("--git-dir=".length);
    expect(lsArgs).toEqual([
      "-c",
      "http.followRedirects=false",
      ...FORCED,
      expect.stringMatching(/^--git-dir=.+harpoc-git-relay-/),
      "ls-remote",
      "--symref",
      "--",
      "https://8.8.8.8/org/repo.git",
      "HEAD",
    ]);
    expect(fetchArgs).toEqual([
      "-c",
      "http.followRedirects=false",
      ...FORCED,
      expect.stringMatching(/^--git-dir=.+harpoc-git-relay-/),
      "fetch",
      "--quiet",
      "--no-write-fetch-head",
      "--depth=1",
      "--",
      "https://8.8.8.8/org/repo.git",
      "+refs/heads/*:refs/heads/*",
      "+refs/tags/*:refs/tags/*",
    ]);
    for (const [, args, opts] of [calls[0], calls[1]] as SpawnCall[]) {
      expect(opts.cwd).toBe((args[8] as string).slice("--git-dir=".length));
      expect(args.some((a) => a.includes("harpoc-f1-dest"))).toBe(false);
      expect(opts.env.GIT_ASKPASS).toBeTruthy();
      expect(opts.env.HARPOC_GIT_PASSWORD).toBe("s3cret-token-value");
    }
    expect(fetchOpts.cwd).toBe(relay);
    expect(lsOpts.cwd).toBe(relay);
    const fileRelay = relay.replace(/\\/g, "/");
    expect(cloneArgs).toEqual([
      ...FORCED,
      // X2: the credential-free local hop speaks no transport but file.
      "-c",
      "protocol.allow=never",
      "-c",
      "protocol.file.allow=always",
      "-c",
      `url.file://${fileRelay.startsWith("/") ? "" : "/"}${fileRelay}.insteadOf=https://8.8.8.8/org/repo.git`,
      "clone",
      "--depth",
      "1",
      "--branch",
      "main",
      "--",
      "https://8.8.8.8/org/repo.git",
      dest,
    ]);
    expect(cloneOpts.cwd).toBeUndefined();
    expect(cloneOpts.env.GIT_ASKPASS).toBeUndefined();
    expect(cloneOpts.env.HARPOC_GIT_PASSWORD).toBeUndefined();
    expect(cloneOpts.env.HARPOC_GIT_USERNAME).toBeUndefined();
    expect(cloneOpts.env.HARPOC_GIT_ORIGIN).toBeUndefined();
    expect(cloneOpts.env.GIT_TERMINAL_PROMPT).toBe("0");
    expect(existsSync(relay)).toBe(false);
  });

  it("S1: the clone options that shape the transfer reach the relay's fetch, normalized; the rest stay with the local clone (F-1)", async () => {
    const args = [
      "--dep",
      "2",
      "--shallow-since=2020-01-01",
      "--shallow-exclude",
      "old",
      "--no-tags",
      "-4",
      "--server-option=trace",
      "-o",
      "upstream",
      "--branch",
      "main",
      "--single-branch",
      "-qn",
    ];
    await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: "https://8.8.8.8/org/repo.git",
        args,
        working_directory: join(tmpdir(), "harpoc-f1-dest"),
      },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
    );
    const calls = spawnMock.mock.calls as SpawnCall[];
    const [, fetchArgs] = calls[1] as SpawnCall;
    expect(fetchArgs.slice(fetchArgs.indexOf("fetch"))).toEqual([
      "fetch",
      "--quiet",
      "--no-write-fetch-head",
      "--depth=2",
      "--shallow-since=2020-01-01",
      "--shallow-exclude=old",
      "--no-tags",
      "--ipv4",
      "--server-option=trace",
      "--",
      "https://8.8.8.8/org/repo.git",
      "+refs/heads/*:refs/heads/*",
    ]);
    const [, cloneArgs] = calls[2] as SpawnCall;
    expect(cloneArgs.slice(cloneArgs.indexOf("clone") + 1, cloneArgs.indexOf("--"))).toEqual(args);

    spawnMock.mockClear();
    await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: "https://8.8.8.8/org/repo.git",
        args: ["--mirror"],
        working_directory: join(tmpdir(), "harpoc-f1-dest"),
      },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
    );
    const [, mirrorFetch] = (spawnMock.mock.calls as SpawnCall[])[1] as SpawnCall;
    expect(mirrorFetch.slice(mirrorFetch.indexOf("--"))).toEqual([
      "--",
      "https://8.8.8.8/org/repo.git",
      "+refs/*:refs/*",
    ]);
  });

  it.each([
    {
      remote: "a symref HEAD",
      listing: `ref: refs/heads/trunk\tHEAD\n${"a".repeat(40)}\tHEAD\n`,
      fetchHead: "ref: refs/heads/trunk\n",
      cloneHead: "ref: refs/heads/trunk\n",
      sha256: false,
      extraRefspec: [],
    },
    {
      remote: "a sha256 repository",
      listing: `ref: refs/heads/main\tHEAD\n${"b".repeat(64)}\tHEAD\n`,
      fetchHead: "ref: refs/heads/main\n",
      cloneHead: "ref: refs/heads/main\n",
      sha256: true,
      extraRefspec: [],
    },
    {
      remote: "a detached HEAD",
      listing: `${"c".repeat(40)}\tHEAD\n`,
      fetchHead: "ref: refs/heads/master\n",
      cloneHead: `${"c".repeat(40)}\n`,
      sha256: false,
      extraRefspec: ["+HEAD:refs/harpoc/remote-head"],
    },
    {
      remote: "an empty repository",
      listing: "",
      fetchHead: "ref: refs/heads/master\n",
      cloneHead: "ref: refs/heads/master\n",
      sha256: false,
      extraRefspec: [],
    },
    // X4b: a symref that is no well-formed refname is not written into the relay;
    // the advertised oid is taken as a detached HEAD instead.
    {
      remote: "a HEAD symref that is no well-formed refname",
      listing: `ref: refs/heads/../../x\tHEAD\n${"d".repeat(40)}\tHEAD\n`,
      fetchHead: "ref: refs/heads/master\n",
      cloneHead: `${"d".repeat(40)}\n`,
      sha256: false,
      extraRefspec: ["+HEAD:refs/harpoc/remote-head"],
    },
  ])(
    "S1: the relay follows $remote as ls-remote reports it (F-1)",
    async ({ listing, fetchHead, cloneHead, sha256, extraRefspec }) => {
      const seen: {
        lsRelay?: string;
        fetchRelay?: string;
        fetchHead?: string;
        config?: string;
        cloneHead?: string;
      } = {};
      spawnMock.mockImplementation((_cmd, args) => {
        const sub = gitSubcommand(args);
        if (sub === "ls-remote") {
          seen.lsRelay = (args[8] as string).slice("--git-dir=".length);
          return Promise.resolve({ ...OK_RESULT, stdout: listing });
        }
        if (sub === "fetch") {
          seen.fetchRelay = (args[8] as string).slice("--git-dir=".length);
          seen.fetchHead = readFileSync(join(seen.fetchRelay, "HEAD"), "utf8");
          seen.config = readFileSync(join(seen.fetchRelay, "config"), "utf8");
          expect(args.slice(args.indexOf("--") + 2)).toEqual([
            "+refs/heads/*:refs/heads/*",
            "+refs/tags/*:refs/tags/*",
            ...extraRefspec,
          ]);
        }
        if (sub === "clone") {
          seen.cloneHead = readFileSync(join(seen.fetchRelay as string, "HEAD"), "utf8");
        }
        return Promise.resolve(OK_RESULT);
      });
      await injector.executeWithSecret(
        {
          type: "git",
          operation: "clone",
          repository: "https://8.8.8.8/org/repo.git",
          working_directory: join(tmpdir(), "harpoc-f1-dest"),
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
        undefined,
      );
      expect(seen.fetchHead).toBe(fetchHead);
      expect(seen.cloneHead).toBe(cloneHead);
      expect(seen.config?.includes("objectFormat = sha256")).toBe(sha256);
      expect(seen.fetchRelay === seen.lsRelay).toBe(!sha256);
      expect(existsSync(seen.lsRelay as string)).toBe(false);
      expect(existsSync(seen.fetchRelay as string)).toBe(false);
    },
  );

  it("S1: a pull's one credential-bearing step fetches the remote's HEAD into the relay; the final pull reads the relay without the credential", async () => {
    const wd = initRepo();
    relayWithRealProbes();
    try {
      const result = await injector.executeWithSecret(
        {
          type: "git",
          operation: "pull",
          repository: "https://8.8.8.8/org/repo.git",
          args: ["--ff-only"],
          working_directory: wd,
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
        undefined,
      );

      expect(result.exit_code).toBe(0);
      const calls = spawnMock.mock.calls as SpawnCall[];
      expect(calls.map(([, a]) => gitSubcommand(a))).toEqual([
        "rev-parse",
        "for-each-ref",
        "fetch",
        "pull",
      ]);
      const [, fetchArgs, fetchOpts] = calls[2] as SpawnCall;
      expect(fetchArgs).toEqual([
        "-c",
        "http.followRedirects=false",
        ...FORCED,
        expect.stringMatching(/^--git-dir=.+harpoc-git-relay-/),
        "fetch",
        "--quiet",
        "--no-write-fetch-head",
        "--",
        "https://8.8.8.8/org/repo.git",
        "+HEAD:refs/heads/harpoc-relay",
      ]);
      const relay = (fetchArgs[8] as string).slice("--git-dir=".length);
      expect(fetchOpts.cwd).toBe(relay);
      expect(fetchOpts.env.HARPOC_GIT_PASSWORD).toBe("s3cret-token-value");

      const [, pullArgs, pullOpts] = calls[3] as SpawnCall;
      expect(pullArgs).toEqual([
        ...FORCED,
        // X2: the credential-free local hop speaks no transport but file.
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=always",
        "-c",
        `url.${relay.replace(/\\/g, "/")}.insteadOf=https://8.8.8.8/org/repo.git`,
        "pull",
        "--ff-only",
        "--",
        "https://8.8.8.8/org/repo.git",
      ]);
      for (const [, , opts] of [calls[0], calls[1], calls[3]] as SpawnCall[]) {
        expect(opts.cwd).toBe(wd);
        expect(opts.env.GIT_ASKPASS).toBeUndefined();
        expect(opts.env.HARPOC_GIT_PASSWORD).toBeUndefined();
        expect(opts.env.HARPOC_GIT_USERNAME).toBeUndefined();
      }
      expect(pullOpts.env.GIT_TERMINAL_PROMPT).toBe("0");
    } finally {
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("S1: the relay is vault-written — its own config, the caller's objects as an alternate, the caller's refs as tips — and gone after the call", async () => {
    const wd = initRepo();
    execFileSync(GIT as string, ["-C", wd, "commit", "-q", "--allow-empty", "-m", "tip"], {
      env: {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG,
        GIT_AUTHOR_NAME: "t",
        GIT_AUTHOR_EMAIL: "t@example.com",
        GIT_COMMITTER_NAME: "t",
        GIT_COMMITTER_EMAIL: "t@example.com",
      },
    });
    const tip = execFileSync(GIT as string, ["-C", wd, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
    let relay = "";
    let seen: { config: string; alternates: string; packedRefs: string; head: string } | null =
      null;
    spawnMock.mockImplementation((cmd, args, opts) => {
      if (gitSubcommand(args) === "fetch") {
        relay = (args.find((a) => a.startsWith("--git-dir=")) as string).slice(10);
        seen = {
          config: readFileSync(join(relay, "config"), "utf8"),
          alternates: readFileSync(join(relay, "objects", "info", "alternates"), "utf8"),
          packedRefs: readFileSync(join(relay, "packed-refs"), "utf8"),
          head: readFileSync(join(relay, "HEAD"), "utf8"),
        };
        return Promise.resolve(OK_RESULT);
      }
      if (gitSubcommand(args) === "pull") return Promise.resolve(OK_RESULT);
      return realSpawnCaptured(cmd, args, opts);
    });
    try {
      await injector.executeWithSecret(
        {
          type: "git",
          operation: "pull",
          repository: "https://8.8.8.8/org/repo.git",
          working_directory: wd,
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
        undefined,
      );
      expect(seen).not.toBeNull();
      const files = seen as unknown as {
        config: string;
        alternates: string;
        packedRefs: string;
        head: string;
      };
      expect(files.config).toBe(
        [
          "[core]",
          "\trepositoryformatversion = 0",
          "\tbare = true",
          "\talternateRefsCommand = : no alternate refs",
          "[push]",
          "\tdefault = current",
          "[gc]",
          "\tauto = 0",
          "[maintenance]",
          "\tauto = false",
          "",
        ].join("\n"),
      );
      expect(realpathSync.native(files.alternates.trim())).toBe(
        realpathSync.native(join(wd, ".git", "objects")),
      );
      expect(files.packedRefs).toMatch(new RegExp(`^${tip} refs/harpoc/local/heads/`));
      expect(files.head).toBe("ref: refs/heads/harpoc-relay\n");
      expect(existsSync(relay)).toBe(false);
    } finally {
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("S1: the pull options that shape the fetch reach the network step too, normalized; the rest stay with the local pull", async () => {
    const wd = initRepo();
    relayWithRealProbes();
    const args = [
      "--tags",
      // A separate value would be a positional, which a pull refuses (X2).
      "--depth=3",
      "-4",
      "--rebase",
      "-Xtheirs",
      "--shallow-since=2020-01-01",
    ];
    try {
      await injector.executeWithSecret(
        {
          type: "git",
          operation: "pull",
          repository: "https://8.8.8.8/org/repo.git",
          args,
          working_directory: wd,
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
        undefined,
      );
      const calls = spawnMock.mock.calls as SpawnCall[];
      const [, fetchArgs] = calls.find(([, a]) => gitSubcommand(a) === "fetch") as SpawnCall;
      const fetchTail = fetchArgs.slice(fetchArgs.indexOf("fetch"));
      expect(fetchTail).toEqual([
        "fetch",
        "--quiet",
        "--no-write-fetch-head",
        "--tags",
        "--depth=3",
        "--ipv4",
        "--shallow-since=2020-01-01",
        "--",
        "https://8.8.8.8/org/repo.git",
        "+HEAD:refs/heads/harpoc-relay",
      ]);
      const [, pullArgs] = calls.find(([, a]) => gitSubcommand(a) === "pull") as SpawnCall;
      expect(pullArgs.slice(pullArgs.indexOf("pull"))).toEqual([
        "pull",
        ...args,
        "--",
        "https://8.8.8.8/org/repo.git",
      ]);
    } finally {
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it.each([
    ["-rt", false],
    ["-t", true],
  ])("S1b: pull %s forwards --tags to the network fetch: %s", async (arg, forwarded) => {
    const wd = initRepo();
    relayWithRealProbes();
    try {
      await injector.executeWithSecret(
        {
          type: "git",
          operation: "pull",
          repository: "https://8.8.8.8/org/repo.git",
          args: [arg as string],
          working_directory: wd,
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
        undefined,
      );
      const calls = spawnMock.mock.calls as SpawnCall[];
      const [, fetchArgs] = calls.find(([, a]) => gitSubcommand(a) === "fetch") as SpawnCall;
      expect(fetchArgs.slice(fetchArgs.indexOf("fetch")).includes("--tags")).toBe(forwarded);
    } finally {
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("skips a 1-2 char username in the redaction set (would shred output)", async () => {
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "https://8.8.8.8/org/repo.git",
    };
    await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("ab:s3cret-token-value")),
      policy({
        command_allowlist: [GIT as string],
        url_allowlist: ["https://8.8.8.8/*"],
      }),
      undefined,
    );

    const [, , opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(opts.redact).toContain("s3cret-token-value");
    expect(opts.redact).not.toContain("ab");
  });

  it("redacts a username at the shared floor (MIN_REDACTABLE_FRAGMENT)", async () => {
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "https://8.8.8.8/org/repo.git",
    };
    await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("abc:s3cret-token-value")),
      policy({
        command_allowlist: [GIT as string],
        url_allowlist: ["https://8.8.8.8/*"],
      }),
      undefined,
    );

    const [, , opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(opts.redact).toContain("s3cret-token-value");
    expect(opts.redact).toContain("abc");
  });
});

// H6: target control for Git-over-HTTPS must survive past the initially supplied
// URL string. git asks askpass for whatever host it ends up talking to (after a
// 3xx, or for a submodule URL the cloned repo chose), so the credential is bound
// to the validated host and redirect following is turned off.
describeGit("GitInjector HTTPS target control beyond the URL string (H6)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  const REPO = "https://8.8.8.8/org/repo.git";
  const CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

  function httpsPolicy(): InjectionPolicy {
    return policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] });
  }

  /** Run the vault-authored askpass helper the way its launcher does. */
  function askpass(env: Record<string, string>, prompt: string): { out: string; status: number } {
    const helper = join(dirname(env.GIT_ASKPASS as string), "askpass.mjs");
    const r = spawnSync(process.execPath, [helper, prompt], { env, encoding: "utf8" });
    return { out: r.stdout ?? "", status: r.status ?? -1 };
  }

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("forces http.followRedirects=false ahead of the subcommand", async () => {
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );
    // Both credential-bearing steps of the clone (ls-remote, fetch) carry it.
    for (const [, args] of (spawnMock.mock.calls as SpawnCall[]).slice(0, 2)) {
      expect(args.slice(0, 2)).toEqual(["-c", "http.followRedirects=false"]);
      // The forced config must precede the subcommand or git ignores it.
      expect(args.indexOf(gitSubcommand(args) as string)).toBeGreaterThan(
        args.indexOf("http.followRedirects=false"),
      );
    }
  });

  it("pins a stored git CA through vault-authored config, on a 0600 file that is removed after the call", async () => {
    let caPathSeen: string | undefined;
    let caContent: string | undefined;
    let caMode: number | undefined;
    spawnMock.mockImplementationOnce(async (_cmd: string, args: string[]) => {
      const at = args.indexOf("-c", 2);
      caPathSeen = args[at + 1]?.replace(/^http\.sslCAInfo=/, "");
      if (caPathSeen) {
        caContent = readFileSync(caPathSeen, "utf8");
        caMode = statSync(caPathSeen).mode & 0o777;
      }
      return OK_RESULT;
    });

    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      { git: { ca_pem: CA_PEM } },
    );

    const caConfig = [
      "-c",
      "http.followRedirects=false",
      "-c",
      `http.sslCAInfo=${caPathSeen}`,
      "-c",
      "http.schannelUseSSLCAInfo=true",
      ...(process.platform === "win32"
        ? ["-c", "http.sslBackend=schannel", "-c", "http.schannelCheckRevoke=best-effort"]
        : []),
    ];
    // Both credential-bearing steps of the clone (ls-remote, fetch) carry the pin.
    for (const [, args] of (spawnMock.mock.calls as SpawnCall[]).slice(0, 2)) {
      expect(args.slice(0, caConfig.length)).toEqual(caConfig);
      expect(args.slice(caConfig.length, caConfig.length + 6)).toEqual(FORCED);
      expect(args[caConfig.length + 6]).toMatch(/^--git-dir=/);
      expect(args.indexOf(gitSubcommand(args) as string)).toBe(caConfig.length + 7);
    }
    expect(caContent).toBe(CA_PEM);
    if (process.platform !== "win32") expect(caMode).toBe(0o600);
    expect(existsSync(caPathSeen as string)).toBe(false);
  });

  it("adds no CA config when the connection config has no git group", async () => {
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      { database: { tls_mode: "require" } },
    );
    const calls = spawnMock.mock.calls as SpawnCall[];
    expect(calls.every(([, a]) => !a.join(" ").includes("sslCAInfo"))).toBe(true);
    for (const [, args] of calls.slice(0, 2)) {
      expect(args[8]).toMatch(/^--git-dir=/);
      expect(args.indexOf(gitSubcommand(args) as string)).toBe(9);
    }
  });

  it("leaves the TLS backend to the host's git when no CA is pinned", async () => {
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );
    const [, args] = spawnMock.mock.calls[0] as SpawnCall;
    expect(args.join(" ")).not.toContain("http.sslBackend=");
    expect(args.join(" ")).not.toContain("http.schannelCheckRevoke=");
  });

  it("N11: forces core.hooksPath to an empty vault-authored directory that exists only for the run", async () => {
    let hooksDir: string | undefined;
    let entriesAtSpawn: string[] | undefined;
    const seenDirs = new Set<string>();
    // Every step of the clone — ls-remote, fetch, the local clone — carries it.
    spawnMock.mockImplementation(async (_cmd: string, args: string[]) => {
      const at = args.findIndex((a) => a.startsWith("core.hooksPath="));
      hooksDir = args[at]?.slice("core.hooksPath=".length);
      expect(args[at - 1]).toBe("-c");
      expect(at).toBeLessThan(args.indexOf(gitSubcommand(args) as string));
      if (hooksDir) {
        seenDirs.add(hooksDir);
        entriesAtSpawn = readdirSync(hooksDir);
      }
      return OK_RESULT;
    });

    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );

    expect(spawnMock).toHaveBeenCalledTimes(3);
    expect(seenDirs.size).toBe(1);
    expect(hooksDir).toBeDefined();
    expect(entriesAtSpawn).toEqual([]);
    expect(existsSync(hooksDir as string)).toBe(false);
  });

  it("N11: every step of a pull into a caller-supplied working tree carries the forced hooksPath", async () => {
    const wd = initRepo();
    relayWithRealProbes();
    try {
      await injector.executeWithSecret(
        {
          type: "git",
          operation: "pull",
          repository: REPO,
          working_directory: wd,
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        httpsPolicy(),
        undefined,
      );
      const calls = spawnMock.mock.calls as SpawnCall[];
      expect(calls).toHaveLength(4);
      for (const [, args] of calls) {
        const at = args.findIndex((a) => a.startsWith("core.hooksPath="));
        expect(at).toBeGreaterThan(0);
        expect(args[at - 1]).toBe("-c");
        expect(at).toBeLessThan(args.indexOf(gitSubcommand(args) as string));
      }
      expect((calls[3] as SpawnCall)[2].cwd).toBe(wd);
    } finally {
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("marks the audited result row ca_pinned when a stored CA is pinned", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      { git: { ca_pem: CA_PEM } },
      "secret-1",
    );
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ transport: "https", ca_pinned: true }),
      }),
    );
  });

  it("marks the audited spawn-refusal row ca_pinned too", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        { type: "git", operation: "clone", repository: REPO },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        httpsPolicy(),
        { git: { ca_pem: CA_PEM } },
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          ca_pinned: true,
        }),
      }),
    );
  });

  it("marks the audited result row sanitized when the spawn seam redacted output", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, redacted: true });
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({ transport: "https", sanitized: true });
  });

  it("leaves sanitized out of the row entirely when nothing was redacted", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect("sanitized" in row.detail).toBe(false);
    expect("descendant_sweep" in row.detail).toBe(false);
  });

  it("carries the descendant sweep's outcome onto the https row of a timed-out spawn", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: null,
      timed_out: true,
      signal: "SIGKILL",
      descendant_sweep: { killed: 0, failed: true },
    });
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({
      transport: "https",
      exit_code: null,
      descendant_sweep: { killed: 0, failed: true },
    });
  });

  it("carries the spawn tier onto the https row as tree_kill (2026-09-10)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, tree_kill: "job" });
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({ transport: "https", tree_kill: "job" });
  });

  it("writes no tree_kill key on the https row when the result carries none (POSIX)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect("tree_kill" in row.detail).toBe(false);
  });

  it("threads the policy's strict_tree_exit into the https spawn seam and onto the row (D2, 2026-09-10)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, tree_kill: "job", strict_tree_exit: true });
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      { ...httpsPolicy(), strict_tree_exit: true },
      undefined,
      "secret-1",
    );
    expect(spawnMock.mock.calls[0]?.[2]).toMatchObject({ strictTreeExit: true });
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({
      transport: "https",
      tree_kill: "job",
      strict_tree_exit: true,
    });
  });

  it("writes no strict_tree_exit key on the https row when the result carries none", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
      "secret-1",
    );
    expect(spawnMock.mock.calls[0]?.[2]).not.toHaveProperty("strictTreeExit", true);
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect("strict_tree_exit" in row.detail).toBe(false);
  });

  it("binds the credential to the validated origin", async () => {
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );
    const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
    expect(opts.env.HARPOC_GIT_ORIGIN).toBe("https://8.8.8.8");
  });

  it("the askpass helper answers for the validated host and refuses any other", async () => {
    let captured: Record<string, string> | undefined;
    let answered: { out: string; status: number } | undefined;
    let refused: { out: string; status: number } | undefined;
    let refusedNoUrl: { out: string; status: number } | undefined;

    // The launcher only exists for the duration of the spawn, so exercise it here —
    // in the credential-bearing steps; the clone's local step carries no askpass.
    spawnMock.mockImplementation((_cmd, _args, opts) => {
      if ((opts as { env: Record<string, string> }).env.GIT_ASKPASS === undefined) {
        return Promise.resolve(OK_RESULT);
      }
      captured = (opts as { env: Record<string, string> }).env;
      answered = askpass(captured, "Password for 'https://git-user@8.8.8.8': ");
      refused = askpass(captured, "Password for 'https://8.8.8.8.attacker.tld/leak': ");
      refusedNoUrl = askpass(captured, "Password: ");
      return Promise.resolve(OK_RESULT);
    });

    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );

    expect(answered?.out.trim()).toBe("s3cret-token-value");
    expect(answered?.status).toBe(0);
    // A redirect or submodule target must get nothing, and the helper must fail.
    expect(refused?.out).not.toContain("s3cret-token-value");
    expect(refused?.out.trim()).toBe("");
    expect(refused?.status).toBe(1);
    // Fail closed when the prompt names no recognizable URL.
    expect(refusedNoUrl?.out.trim()).toBe("");
    expect(refusedNoUrl?.status).toBe(1);
  });

  it("answers the username prompt for the validated host too", async () => {
    let answered: { out: string; status: number } | undefined;
    spawnMock.mockImplementation((_cmd, _args, opts) => {
      if ((opts as { env: Record<string, string> }).env.GIT_ASKPASS === undefined) {
        return Promise.resolve(OK_RESULT);
      }
      answered = askpass(
        (opts as { env: Record<string, string> }).env,
        "Username for 'https://8.8.8.8': ",
      );
      return Promise.resolve(OK_RESULT);
    });
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: REPO },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      httpsPolicy(),
      undefined,
    );
    expect(answered?.out.trim()).toBe("git-user");
  });

  it.each(["--recurse-submodules", "--recursive", "--recurse-sub"])(
    "refuses %s — submodule URLs come from the repository, not the vault",
    async (arg) => {
      await expect(
        injector.executeWithSecret(
          { type: "git", operation: "clone", repository: REPO, args: [arg] },
          new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
          httpsPolicy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
      expect(spawnMock).not.toHaveBeenCalled();
    },
  );
});

describeGitSsh("GitInjector SSH transport hardening (git + ssh resolvable)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("wires GIT_SSH_COMMAND with the hardening args and the agent socket", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
    };
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "git@github.com:org/repo.git",
    };

    const result = await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from(keyPem)),
      policy({
        command_allowlist: [GIT as string],
        host_allowlist: ["github.com"],
      }),
      config,
    );

    expect(result.exit_code).toBe(0);
    const calls = spawnMock.mock.calls as SpawnCall[];
    // ls-remote and fetch run over the agent in the relay; the clone is made from it (F-1).
    expect(calls.map(([, a]) => gitSubcommand(a))).toEqual(["ls-remote", "fetch", "clone"]);
    const [, lsArgs] = calls[0] as SpawnCall;
    expect(lsArgs).toEqual([
      ...FORCED,
      expect.stringMatching(/^--git-dir=.+harpoc-git-relay-/),
      "ls-remote",
      "--symref",
      "--",
      "git@github.com:org/repo.git",
      "HEAD",
    ]);

    for (const [command, , opts] of calls.slice(0, 2)) {
      expect(command).toBe(GIT);
      const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
      expect(sshCommand).toContain("StrictHostKeyChecking=yes");
      expect(sshCommand).toContain(" -o GlobalKnownHostsFile=none ");
      expect(sshCommand).toContain("BatchMode=yes");
      expect(sshCommand).toContain("UserKnownHostsFile=");
      expect(sshCommand).toContain("IdentitiesOnly=yes");
      // IdentitiesOnly restricts ssh to file-backed identities — the vault-written
      // .pub must ride along in GIT_SSH_COMMAND or the agent key is never offered.
      expect(sshCommand).toMatch(/ -i "?[^"]*identity\.pub"?/);
      expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
      expect(opts.env.GIT_TERMINAL_PROMPT).toBe("0");
      expect(opts.redact).toContain(keyPem);
    }
    const [, cloneArgs, cloneOpts] = calls[2] as SpawnCall;
    expect(cloneArgs.slice(cloneArgs.indexOf("clone"))).toEqual([
      "clone",
      "--",
      "git@github.com:org/repo.git",
    ]);
    expect(cloneOpts.env.SSH_AUTH_SOCK).toBeUndefined();
    expect(cloneOpts.env.GIT_SSH_COMMAND).toBeUndefined();

    // The private key reaches ssh only through the ephemeral agent socket.
    for (const [, args, opts] of calls) {
      expect(args.every((a) => !a.includes("PRIVATE KEY"))).toBe(true);
      expect(Object.values(opts.env).every((v) => !v.includes("PRIVATE KEY"))).toBe(true);
    }
  });

  it("push: the network step is the forced config, --git-dir of the relay, the operation, the caller's options, `--`, then the repository, over the agent; the working-tree steps have no agent (I18, S1)", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const wd = initRepo();
    relayWithRealProbes();
    try {
      const result = await injector.executeWithSecret(
        {
          type: "git",
          operation: "push",
          repository: "git@github.com:org/repo.git",
          args: ["--force-with-lease", "--follow-tags"],
          working_directory: wd,
        },
        new Uint8Array(Buffer.from(keyPem)),
        policy({
          command_allowlist: [GIT as string],
          host_allowlist: ["github.com"],
        }),
        { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
      );

      expect(result.exit_code).toBe(0);
      const calls = spawnMock.mock.calls as SpawnCall[];
      expect(calls.map(([, a]) => gitSubcommand(a))).toEqual([
        "rev-parse",
        "symbolic-ref",
        "for-each-ref",
        "push",
      ]);
      const [command, args, opts] = calls[3] as SpawnCall;
      expect(command).toBe(GIT);
      expect(args).toEqual([
        ...FORCED,
        expect.stringMatching(/^--git-dir=.+harpoc-git-relay-/),
        "push",
        "--force-with-lease",
        "--follow-tags",
        "--",
        "git@github.com:org/repo.git",
      ]);
      expect(opts.env.GIT_SSH_COMMAND).toContain("IdentitiesOnly=yes");
      expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
      expect(opts.env.GIT_CONFIG_NOSYSTEM).toBe("1");
      expect(opts.env.GIT_CONFIG_GLOBAL).toBe(NULL_GIT_CONFIG);
      expect(Object.values(opts.env).every((v) => !v.includes("PRIVATE KEY"))).toBe(true);
      for (const [, , localOpts] of calls.slice(0, 3)) {
        expect(localOpts.cwd).toBe(wd);
        expect(localOpts.env.SSH_AUTH_SOCK).toBeUndefined();
        expect(localOpts.env.GIT_SSH_COMMAND).toBeUndefined();
        expect(localOpts.env.GIT_CONFIG_NOSYSTEM).toBe("1");
        expect(localOpts.env.GIT_CONFIG_GLOBAL).toBe(NULL_GIT_CONFIG);
      }
    } finally {
      rmSync(wd, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("hands git a built environment over SSH, not the vault's own", async () => {
    process.env.HARPOC_T14_GIT_SSH_AMBIENT = "ambient-value";
    process.env.HARPOC_T14_GIT_SSH_ALLOWED = "allowed-value";
    try {
      const { privateKey: keyPem } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs1", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      await injector.executeWithSecret(
        { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
        new Uint8Array(Buffer.from(keyPem)),
        policy({
          command_allowlist: [GIT as string],
          host_allowlist: ["github.com"],
          env_allowlist: ["HARPOC_T14_GIT_SSH_ALLOWED"],
        }),
        { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
      );

      const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
      expect(opts.env.HARPOC_T14_GIT_SSH_AMBIENT).toBeUndefined();
      expect(opts.env.HARPOC_T14_GIT_SSH_ALLOWED).toBe("allowed-value");

      const expected = new Set([
        "PATH",
        ...(process.platform === "win32" ? ["SystemRoot", "ProgramData"] : []),
        "SSH_AUTH_SOCK",
        "GIT_SSH_COMMAND",
        "GIT_TERMINAL_PROMPT",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "HARPOC_T14_GIT_SSH_ALLOWED",
      ]);
      expect(Object.keys(opts.env).filter((k) => !expected.has(k))).toEqual([]);
    } finally {
      delete process.env.HARPOC_T14_GIT_SSH_AMBIENT;
      delete process.env.HARPOC_T14_GIT_SSH_ALLOWED;
    }
  });

  it("N11: the SSH transport forces core.hooksPath as well, and removes the directory after the run", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    let hooksDir: string | undefined;
    let entriesAtSpawn: string[] | undefined;
    spawnMock.mockImplementationOnce(async (_cmd: string, args: string[]) => {
      hooksDir = args.find((a) => a.startsWith("core.hooksPath="))?.slice("core.hooksPath=".length);
      if (hooksDir) entriesAtSpawn = readdirSync(hooksDir);
      return OK_RESULT;
    });

    await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: "git@github.com:org/repo.git",
      },
      new Uint8Array(Buffer.from(keyPem)),
      policy({
        command_allowlist: [GIT as string],
        host_allowlist: ["github.com"],
      }),
      {
        ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
      },
    );

    expect(hooksDir).toBeDefined();
    expect(entriesAtSpawn).toEqual([]);
    expect(existsSync(hooksDir as string)).toBe(false);
  });

  it("normalizes GIT_SSH_COMMAND to forward-slash paths git's bundled sh can exec", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
    };
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "git@github.com:org/repo.git",
    };

    await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from(keyPem)),
      policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
      config,
    );

    const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
    const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
    // Git-for-Windows runs GIT_SSH_COMMAND through sh, which treats a backslash
    // as an escape: on win32 the real ssh binary and the temp identity /
    // known_hosts paths are backslashed and must be normalized or the command
    // fails to exec (harness-discovered, Phase 2). POSIX paths have none, so the
    // assertion holds on every platform and guards the win32 fix from regressing.
    expect(sshCommand).not.toContain("\\");
    expect(sshCommand).toContain("UserKnownHostsFile=");
    expect(sshCommand).toMatch(/ -i "?'?[^"']*identity\.pub'?"?/);
  });

  // Review 2026-08-12: the win32 forward-slash fix still broke for paths sh or
  // ssh re-split — sh word-splits unquoted whitespace and expands `$`/backtick
  // even inside double quotes, and ssh's readconf re-tokenizes the
  // UserKnownHostsFile VALUE on whitespace after sh has built the argv. Parts
  // are now single-quoted for sh, the known_hosts value additionally
  // double-quoted for readconf.
  it("single-quotes GIT_SSH_COMMAND parts sh would split or expand; known_hosts value stays readconf-quoted", async () => {
    const spaced = mkdtempSync(join(tmpdir(), "harpoc sh $probe-"));
    const saved = overrideTempEnv(spaced);
    try {
      const { privateKey: keyPem } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs1", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      await injector.executeWithSecret(
        { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
        new Uint8Array(Buffer.from(keyPem)),
        policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
        { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
      );

      const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
      const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
      const spacedFwd = spaced.replace(/\\/g, "/");

      // known_hosts part: single quotes for sh around a readconf-quoted value.
      const kh = /'UserKnownHostsFile="([^"]+)"'/.exec(sshCommand);
      expect(kh, sshCommand).toBeTruthy();
      expect((kh as RegExpExecArray)[1]).toContain(spacedFwd);
      // identity part: one single-quoted sh word after -i.
      const id = / -i '([^']+identity\.pub)'/.exec(sshCommand);
      expect(id, sshCommand).toBeTruthy();
      expect((id as RegExpExecArray)[1]).toContain(spacedFwd);
      // Nothing space-bearing or expandable survives outside single quotes.
      const outsideQuotes = sshCommand.replace(/'[^']*'/g, "");
      expect(outsideQuotes).not.toContain(spacedFwd);
      expect(outsideQuotes).not.toContain("$");
    } finally {
      restoreTempEnv(saved);
      rmSync(spaced, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  // Real-sh round trip: the composed string must split back into exactly the
  // intended argv under the same shell git uses. POSIX always has /bin/sh; on
  // Windows the Git-for-Windows sh is probed (attempt-and-skip when absent).
  it.skipIf(findRoundtripSh() === null)(
    "composes a GIT_SSH_COMMAND real sh splits back into the intended argv",
    async () => {
      const sh = findRoundtripSh() as string;
      const spaced = mkdtempSync(join(tmpdir(), "harpoc sh $probe-"));
      const saved = overrideTempEnv(spaced);
      try {
        const { privateKey: keyPem } = generateKeyPairSync("rsa", {
          modulusLength: 2048,
          privateKeyEncoding: { type: "pkcs1", format: "pem" },
          publicKeyEncoding: { type: "spki", format: "pem" },
        });
        await injector.executeWithSecret(
          { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
          new Uint8Array(Buffer.from(keyPem)),
          policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
          { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
        );

        const [, , opts] = spawnMock.mock.calls[0] as SpawnCall;
        const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
        const out = execFileSync(sh, ["-c", `printf '%s\n' ${sshCommand}`], {
          encoding: "utf8",
        });
        const words = out.split("\n").filter((l) => l.length > 0);
        const spacedFwd = spaced.replace(/\\/g, "/");

        // First word execs the ssh binary (forward-slashed on win32).
        expect(words[0]).toBe((SSH as string).replace(/\\/g, "/"));
        // The known_hosts option value survives as ONE argv element with its
        // readconf quotes intact, spaces and all.
        const khWord = words.find((w) => w.startsWith("UserKnownHostsFile="));
        expect(khWord, out).toMatch(/^UserKnownHostsFile="[^"]*known_hosts"$/);
        expect(khWord).toContain(spacedFwd);
        // The identity path survives as ONE argv element right after -i.
        const iIdx = words.indexOf("-i");
        expect(iIdx).toBeGreaterThan(-1);
        expect(words[iIdx + 1]).toMatch(/identity\.pub$/);
        expect(words[iIdx + 1]).toContain(spacedFwd);
        // sh performed no $-expansion: the literal $probe survives.
        expect(words[iIdx + 1]).toContain("$probe");
        const khPath = /^UserKnownHostsFile="([^"]+)"$/.exec(khWord as string)?.[1] as string;
        const hardening = sshHardeningArgs(khPath, words[iIdx + 1] as string, 120);
        expect(words.slice(1, 1 + hardening.length)).toEqual(hardening);
        expect(words).toHaveLength(1 + hardening.length);
      } finally {
        restoreTempEnv(saved);
        rmSync(spaced, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    },
  );

  it("backs the agent identity with a vault-written .pub, removed after the invocation", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    let identityPath = "";
    let identityContentAtSpawn = "";
    spawnMock.mockImplementation((_cmd, _args, opts) => {
      const sshCommand = (opts as { env?: Record<string, string> }).env?.GIT_SSH_COMMAND ?? "";
      // The clone's local step runs without ssh (F-1); the network steps carry it.
      if (sshCommand === "") return Promise.resolve(OK_RESULT);
      // The identity path may be single-quoted for sh, double-quoted, or bare —
      // `toGitSshCommand` quotes only the parts that are not shell-neutral. A
      // CI runner's temp path contains `~` (C:\Users\RUNNER~1\...), so it IS
      // quoted there while a plain developer path is not: matching double
      // quotes alone captured the surrounding quotes as part of the filename
      // and read a path that does not exist.
      const m = / -i (?:"([^"]+)"|'((?:[^']|'\\'')+)'|(\S+))/.exec(sshCommand);
      const raw = (m?.[1] ?? m?.[2] ?? m?.[3]) as string;
      identityPath = raw.replaceAll("'\\''", "'");
      identityContentAtSpawn = readFileSync(identityPath, "utf8");
      return Promise.resolve(OK_RESULT);
    });

    await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: "git@github.com:org/repo.git",
      },
      new Uint8Array(Buffer.from(keyPem)),
      policy({
        command_allowlist: [GIT as string],
        host_allowlist: ["github.com"],
      }),
      { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
    );

    expect(identityContentAtSpawn).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ harpoc-ephemeral\n$/);
    expect(identityContentAtSpawn).not.toContain("PRIVATE KEY");
    expect(existsSync(identityPath)).toBe(false);
  });
});

describeGit("GitInjector network isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const cloneAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "https://8.8.8.8/org/repo.git",
  };

  const isolatedPolicy = () =>
    policy({
      command_allowlist: [GIT as string],
      url_allowlist: ["https://8.8.8.8/*"],
      network_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, isolation_mechanism: "unshare" });
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      isolatedPolicy(),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          transport: "https",
          network_isolation: true,
          isolation_mechanism: "unshare",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        cloneAction,
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        isolatedPolicy(),
        undefined,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits network_isolation: false", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ network_isolation: false }),
      }),
    );
  });
});

describeGit("GitInjector filesystem isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const cloneAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "https://8.8.8.8/org/repo.git",
  };

  const fsIsolatedPolicy = () =>
    policy({
      command_allowlist: [GIT as string],
      url_allowlist: ["https://8.8.8.8/*"],
      fs_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, fs_isolation_mechanism: "landlock" });
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      fsIsolatedPolicy(),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], { fsIsolation?: boolean }];
    expect(opts.fsIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          transport: "https",
          fs_isolation: true,
          fs_isolation_mechanism: "landlock",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.fsIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        cloneAction,
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        fsIsolatedPolicy(),
        undefined,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          transport: "https",
          error: ErrorCode.FS_ISOLATION_UNAVAILABLE,
          fs_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits fs_isolation: false", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], { fsIsolation?: boolean }];
    expect(opts.fsIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ fs_isolation: false }),
      }),
    );
  });
});

// The SSH transport has its own isolation wiring (flag hand-off, refusal
// catch, success/denial audit rows) — per-callsite, so it needs its own pin:
// pre-fix only 3 of the 4 spawnCaptured callsites were covered (review T1).
describeGitSsh("GitInjector SSH-transport network isolation (review fixes T1/F8)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const { privateKey: sshKeyPem } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const sshConfig: ConnectionConfig = {
    ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
  };
  const sshAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "git@github.com:org/repo.git",
  };
  const isolatedSshPolicy = () =>
    policy({
      command_allowlist: [GIT as string],
      host_allowlist: ["github.com"],
      network_isolation: true,
    });
  const plainSshPolicy = () =>
    policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, isolation_mechanism: "unshare" });
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      isolatedSshPolicy(),
      sshConfig,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          transport: "ssh",
          network_isolation: true,
          isolation_mechanism: "unshare",
        }),
      }),
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect("descendant_sweep" in row.detail).toBe(false);
  });

  it("carries the descendant sweep's outcome onto the ssh-transport row of a timed-out spawn", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: null,
      timed_out: true,
      signal: "SIGKILL",
      descendant_sweep: { killed: 2, failed: false },
    });
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      isolatedSshPolicy(),
      sshConfig,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({
      transport: "ssh",
      exit_code: null,
      descendant_sweep: { killed: 2, failed: false },
    });
  });

  it("carries the spawn tier onto the ssh-transport row as tree_kill (2026-09-10)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, tree_kill: "job" });
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      plainSshPolicy(),
      sshConfig,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({ transport: "ssh", tree_kill: "job" });
  });

  it("writes no tree_kill key on the ssh-transport row when the result carries none (POSIX)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      plainSshPolicy(),
      sshConfig,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect("tree_kill" in row.detail).toBe(false);
  });

  it("threads the policy's strict_tree_exit into the ssh-transport spawn seam and onto the row (D2, 2026-09-10)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, tree_kill: "job", strict_tree_exit: true });
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      { ...plainSshPolicy(), strict_tree_exit: true },
      sshConfig,
      "secret-1",
    );
    expect(spawnMock.mock.calls[0]?.[2]).toMatchObject({ strictTreeExit: true });
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({
      transport: "ssh",
      tree_kill: "job",
      strict_tree_exit: true,
    });
  });

  it("writes no strict_tree_exit key on the ssh-transport row when the result carries none", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      plainSshPolicy(),
      sshConfig,
      "secret-1",
    );
    expect(spawnMock.mock.calls[0]?.[2]).not.toHaveProperty("strictTreeExit", true);
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect("strict_tree_exit" in row.detail).toBe(false);
  });

  it("audits and rethrows the fail-closed refusal from the seam (transport ssh)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        sshAction,
        new Uint8Array(Buffer.from(sshKeyPem)),
        isolatedSshPolicy(),
        sshConfig,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          transport: "ssh",
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits network_isolation: false", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      sshAction,
      new Uint8Array(Buffer.from(sshKeyPem)),
      policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
      sshConfig,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ transport: "ssh", network_isolation: false }),
      }),
    );
  });

  it("the host-key-mismatch denial carries the isolation posture (review fix F8)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 128,
      stderr: "Host key verification failed.",
    });
    await expect(
      audited.executeWithSecret(
        sshAction,
        new Uint8Array(Buffer.from(sshKeyPem)),
        isolatedSshPolicy(),
        sshConfig,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_HOST_KEY_MISMATCH });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          transport: "ssh",
          error: "SSH_HOST_KEY_MISMATCH",
          network_isolation: true,
        }),
      }),
    );
  });
});

// The Git-over-SSH callsite threads filesystem isolation independently of the
// HTTPS one — same per-callsite reasoning as review T1 above.
describeGitSsh("GitInjector SSH-transport filesystem isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const { privateKey: fsSshKeyPem } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const fsSshConfig: ConnectionConfig = {
    ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
  };
  const fsSshAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "git@github.com:org/repo.git",
  };
  const fsIsolatedSshPolicy = () =>
    policy({
      command_allowlist: [GIT as string],
      host_allowlist: ["github.com"],
      fs_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, fs_isolation_mechanism: "landlock" });
    await audited.executeWithSecret(
      fsSshAction,
      new Uint8Array(Buffer.from(fsSshKeyPem)),
      fsIsolatedSshPolicy(),
      fsSshConfig,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], { fsIsolation?: boolean }];
    expect(opts.fsIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          transport: "ssh",
          fs_isolation: true,
          fs_isolation_mechanism: "landlock",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam (transport ssh)", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.fsIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        fsSshAction,
        new Uint8Array(Buffer.from(fsSshKeyPem)),
        fsIsolatedSshPolicy(),
        fsSshConfig,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          transport: "ssh",
          error: ErrorCode.FS_ISOLATION_UNAVAILABLE,
          fs_isolation: true,
        }),
      }),
    );
  });

  it("the host-key-mismatch denial carries the filesystem-isolation posture", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 128,
      stderr: "Host key verification failed.",
    });
    await expect(
      audited.executeWithSecret(
        fsSshAction,
        new Uint8Array(Buffer.from(fsSshKeyPem)),
        fsIsolatedSshPolicy(),
        fsSshConfig,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_HOST_KEY_MISMATCH });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          transport: "ssh",
          error: "SSH_HOST_KEY_MISMATCH",
          fs_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits fs_isolation: false", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      fsSshAction,
      new Uint8Array(Buffer.from(fsSshKeyPem)),
      policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
      fsSshConfig,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], { fsIsolation?: boolean }];
    expect(opts.fsIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ transport: "ssh", fs_isolation: false }),
      }),
    );
  });
});

// win32 only: the MSYS/Cygwin client refusal is a win32 product path (a no-op elsewhere).
const describeGitSshWin32 = describe.skipIf(
  GIT === null || SSH === null || process.platform !== "win32",
);

describeGitSshWin32("GitInjector refuses an MSYS/Cygwin ssh client (D58)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const { privateKey: msysKeyPem } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const msysConfig: ConnectionConfig = {
    ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
  };
  const msysAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "git@github.com:org/repo.git",
  };
  const msysPolicy = () =>
    policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] });

  let fixtureDir: string;
  let stub: string;
  const savedPath = process.env.PATH;

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
    fixtureDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-msys-git-ssh-")));
    stub = join(fixtureDir, "ssh.exe");
    writeFileSync(stub, "");
    writeFileSync(join(fixtureDir, "msys-2.0.dll"), "");
    // The stub shadows the real ssh; git must still resolve for the transport dispatch.
    process.env.PATH = `${fixtureDir}${delimiter}${dirname(GIT as string)}`;
  });

  afterEach(() => {
    process.env.PATH = savedPath;
    rmSync(fixtureDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("refuses before any spawn, with a failed secret.use row naming the code", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    await expect(
      audited.executeWithSecret(
        msysAction,
        new Uint8Array(Buffer.from(msysKeyPem)),
        msysPolicy(),
        msysConfig,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_CLIENT_UNSUPPORTED });
    expect(spawnMock).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: "secret.use",
        success: false,
        detail: expect.objectContaining({
          context: "git",
          host: "github.com",
          error: "SSH_CLIENT_UNSUPPORTED",
        }),
      }),
    );
  });

  it("guard-flip: without the DLL the same stub drives GIT_SSH_COMMAND", async () => {
    rmSync(join(fixtureDir, "msys-2.0.dll"));
    const injector = new GitInjector(null);
    await injector.executeWithSecret(
      msysAction,
      new Uint8Array(Buffer.from(msysKeyPem)),
      msysPolicy(),
      msysConfig,
    );
    // The clone's two network steps run over the stub; the local clone has no ssh (F-1).
    expect(spawnMock).toHaveBeenCalledTimes(3);
    for (const [command, , opts] of (spawnMock.mock.calls as SpawnCall[]).slice(0, 2)) {
      expect(command).toBe(GIT);
      expect((opts.env.GIT_SSH_COMMAND ?? "").toLowerCase()).toContain(
        stub.replaceAll("\\", "/").toLowerCase(),
      );
    }
  });
});
