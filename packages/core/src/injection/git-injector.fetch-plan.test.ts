/**
 * M6 (B9): the step plan of a fetch and an ls-remote — every step's argv, cwd
 * and environment, which one carries the credential, the refspec grammar and
 * the one deadline the steps share. The working-tree probes run real git; the
 * network steps and the local fetch answer through a mocked spawn seam.
 */
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { GitInjector, fetchRefspecPlan, parseFetchRefspec } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

// The SSH row resolves ssh as the injector does; on Windows only the native
// Win32-OpenSSH client is accepted, so its directory leads the PATH (as in
// git-injector.spawn.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");
// Skipped where git does not resolve: the working-tree probes run real git; the
// SSH row also needs the native ssh client.
const describeGit = describe.skipIf(GIT === null);
const describeGitSsh = describe.skipIf(GIT === null || SSH === null);

const NULL_GIT_CONFIG = process.platform === "win32" ? "NUL" : "/dev/null";
const REPO = "https://8.8.8.8/org/repo.git";
const TOKEN = "s3cret-token-value";
const MOCKED = ["ls-remote", "fetch"];

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

type SpawnCall = [
  string,
  string[],
  { env: Record<string, string>; cwd?: string; timeoutMs: number; redact?: string[] },
];

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function policy(): InjectionPolicy {
  return {
    url_allowlist: ["https://8.8.8.8/*"],
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
  };
}

describe("fetch refspec grammar (RX-B9-2): the remote's refs only, the vault's destinations", () => {
  it.each([
    ["refs/heads/main", "+refs/heads/main:refs/heads/main", "refs/heads/main:refs/remotes/o/main"],
    [
      "+refs/heads/main",
      "+refs/heads/main:refs/heads/main",
      "+refs/heads/main:refs/remotes/o/main",
    ],
    ["+refs/heads/*", "+refs/heads/*:refs/heads/*", "+refs/heads/*:refs/remotes/o/*"],
    [
      "refs/heads/feature/*",
      "+refs/heads/feature/*:refs/heads/feature/*",
      "refs/heads/feature/*:refs/remotes/o/feature/*",
    ],
    [
      "refs/heads/rel-*-x",
      "+refs/heads/rel-*-x:refs/heads/rel-*-x",
      "refs/heads/rel-*-x:refs/remotes/o/rel-*-x",
    ],
    ["refs/tags/v1.0", "+refs/tags/v1.0:refs/tags/v1.0", "refs/tags/v1.0:refs/tags/v1.0"],
    ["+refs/tags/v*", "+refs/tags/v*:refs/tags/v*", "+refs/tags/v*:refs/tags/v*"],
    ["^refs/heads/wip/*", "^refs/heads/wip/*", "^refs/heads/wip/*"],
    ["^refs/tags/old", "^refs/tags/old", "^refs/tags/old"],
  ])("admits %s: network %s, local %s", (spec, network, local) => {
    expect(fetchRefspecPlan([parseFetchRefspec(spec)], "o")).toEqual({
      network: [network],
      local: [local],
    });
  });

  it("lands a branch under the remote's own name, slashes and dots kept", () => {
    expect(fetchRefspecPlan([parseFetchRefspec("refs/heads/a")], "up.stream/x").local).toEqual([
      "refs/heads/a:refs/remotes/up.stream/x/a",
    ]);
  });

  it.each([
    "main",
    "HEAD",
    "refs/*",
    "refs/remotes/origin/main",
    "refs/notes/commits",
    "refs/pull/1/head",
    "refs/heads/",
    "refs/heads/a:refs/heads/a",
    "refs/heads/a:",
    ":refs/heads/a",
    "tag v1",
    "0123456789abcdef0123456789abcdef01234567",
    "refs/heads/*/*",
    "refs/heads/a..b",
    "refs/heads/.hidden",
    "refs/heads/a.lock",
    "refs/heads/a//b",
    "refs/heads/a b",
    "refs/heads/a\n",
    "refs/heads/a\tb",
    "refs/heads/a\u0000",
    "refs/heads/a.",
    "refs/heads/a/",
    "refs/heads/a~1",
    "refs/heads/a^{}",
    "refs/heads/@{-1}",
    "++refs/heads/a",
    "+^refs/heads/a",
    "^+refs/heads/a",
    "-refs/heads/a",
    "--upload-pack=x",
  ])("refuses %j with a message naming it and nothing else", async (spec) => {
    const err = await expectVaultError(
      () => Promise.resolve(parseFetchRefspec(spec)),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe(`unsupported fetch refspec: ${spec}`);
  });
});

describeGit("fetch and ls-remote step plans (M6)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);
  let scratch: string;
  let wd: string;

  beforeEach(() => {
    scratch = mkdtempSync(join(tmpdir(), "harpoc-fetch-plan-"));
    wd = join(scratch, "wd");
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG };
    execFileSync(GIT as string, ["init", "-q", wd], { env });
    execFileSync(GIT as string, ["-C", wd, "remote", "add", "origin", REPO], { env });
    spawnMock.mockReset();
    spawnMock.mockImplementation((cmd, args, opts) =>
      MOCKED.includes(gitSubcommand(args) ?? "")
        ? Promise.resolve(OK_RESULT)
        : realSpawnCaptured(cmd, args, opts),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const calls = () => spawnMock.mock.calls as SpawnCall[];
  const secret = () => new Uint8Array(Buffer.from(`git-user:${TOKEN}`));

  it("fetch: three credential-free probes in the tree, the one network fetch in the relay, the credential-free local fetch with the vault's refspecs", async () => {
    const result = await injector.executeWithSecret(
      {
        type: "git",
        operation: "fetch",
        repository: REPO,
        args: ["--prune", "--depth=1", "-t"],
        refspecs: ["refs/heads/main", "^refs/heads/wip"],
        working_directory: wd,
      },
      secret(),
      policy(),
      undefined,
    );
    expect(result).toMatchObject({ type: "git", operation: "fetch", exit_code: 0 });
    expect(calls().map(([, a]) => gitSubcommand(a))).toEqual([
      "rev-parse",
      "config",
      "for-each-ref",
      "fetch",
      "fetch",
    ]);
    const [probe, remotes, listing, network, local] = calls();
    for (const step of [probe, remotes, listing, local]) {
      const [, args, opts] = step as SpawnCall;
      expect(opts.cwd).toBe(wd);
      expect(Object.keys(opts.env).some((k) => k.startsWith("HARPOC_GIT_"))).toBe(false);
      expect("GIT_ASKPASS" in opts.env).toBe(false);
      expect(args.some((a) => a.startsWith("--git-dir="))).toBe(false);
    }
    expect((remotes as SpawnCall)[1].slice(-8)).toEqual([
      "config",
      "-z",
      "--name-only",
      "--fixed-value",
      "--get-regexp",
      "--end-of-options",
      "^remote\\..*\\.url$",
      REPO,
    ]);
    const [, netArgs, netOpts] = network as SpawnCall;
    const relay = (netArgs.find((a) => a.startsWith("--git-dir=")) as string).slice(10);
    expect(netOpts.cwd).toBe(relay);
    expect(netOpts.env.HARPOC_GIT_PASSWORD === TOKEN).toBe(true);
    expect(netArgs.slice(netArgs.indexOf("fetch"))).toEqual([
      "fetch",
      "--quiet",
      "--no-write-fetch-head",
      "--depth=1",
      "--tags",
      "--",
      REPO,
      "+refs/heads/main:refs/heads/main",
      "^refs/heads/wip",
    ]);
    const [, localArgs] = local as SpawnCall;
    expect(localArgs).toContain("protocol.allow=never");
    expect(localArgs).toContain(`url.${relay.replace(/\\/g, "/")}.insteadOf=${REPO}`);
    expect(localArgs.slice(localArgs.indexOf("fetch"))).toEqual([
      "fetch",
      "--no-recurse-submodules",
      "--refmap=",
      "--prune",
      "--depth=1",
      "-t",
      "--",
      REPO,
      "refs/heads/main:refs/remotes/origin/main",
      "^refs/heads/wip",
    ]);
    expect(calls().every(([, a]) => a.every((x) => !x.includes(TOKEN)))).toBe(true);
  });

  it("fetch: every option of the fetch's forwarded table reaches the network fetch, normalized and in order; the others stay with the local fetch, which takes the caller's arguments as given (E-36)", async () => {
    const args = [
      "--tags",
      "--no-tags",
      "--unshallow",
      "--update-shallow",
      "--refetch",
      "--ipv4",
      "--ipv6",
      "--prune",
      "--depth=1",
      "--deepen=2",
      "--shallow-since=2020-01-01",
      "--shallow-exclude=old",
      "--server-option=a",
      "-f",
      "-t",
      "-n",
      "-o",
      "-x",
      "-o",
      "-4",
      "-4",
      "-6",
      "-ob",
      "-o4",
    ];
    await injector.executeWithSecret(
      { type: "git", operation: "fetch", repository: REPO, args, working_directory: wd },
      secret(),
      policy(),
      undefined,
    );
    const [, , , network, local] = calls();
    const [, netArgs] = network as SpawnCall;
    const relay = (netArgs.find((a) => a.startsWith("--git-dir=")) as string).slice(10);
    expect(netArgs).toEqual([
      "-c",
      "http.followRedirects=false",
      "-c",
      expect.stringMatching(/^core\.hooksPath=./),
      "-c",
      "credential.helper=",
      "-c",
      "core.fsmonitor=false",
      `--git-dir=${relay}`,
      "fetch",
      "--quiet",
      "--no-write-fetch-head",
      "--tags",
      "--no-tags",
      "--unshallow",
      "--update-shallow",
      "--refetch",
      "--ipv4",
      "--ipv6",
      "--depth=1",
      "--deepen=2",
      "--shallow-since=2020-01-01",
      "--shallow-exclude=old",
      "--server-option=a",
      "--tags",
      "--no-tags",
      "--server-option=-x",
      "--server-option=-4",
      "--ipv4",
      "--ipv6",
      "--server-option=b",
      "--server-option=4",
      "--",
      REPO,
      "+refs/heads/*:refs/heads/*",
    ]);
    const [, localArgs] = local as SpawnCall;
    expect(localArgs.slice(localArgs.indexOf("fetch"))).toEqual([
      "fetch",
      "--no-recurse-submodules",
      "--refmap=",
      ...args,
      "--",
      REPO,
      "+refs/heads/*:refs/remotes/origin/*",
    ]);
  });

  it("fetch: without refspecs every branch, landed under refs/remotes/<remote>/", async () => {
    await injector.executeWithSecret(
      { type: "git", operation: "fetch", repository: REPO, working_directory: wd },
      secret(),
      policy(),
      undefined,
    );
    const [, , , network, local] = calls();
    expect((network as SpawnCall)[1].slice(-1)).toEqual(["+refs/heads/*:refs/heads/*"]);
    expect((local as SpawnCall)[1].slice(-1)).toEqual(["+refs/heads/*:refs/remotes/origin/*"]);
  });

  it("fetch: the local step receives what the earlier steps left of the one budget (RX-B9-8)", async () => {
    let now = 1_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    spawnMock.mockImplementation((cmd, args, opts) => {
      if (gitSubcommand(args) === "fetch") {
        now += 4_000;
        return Promise.resolve(OK_RESULT);
      }
      return realSpawnCaptured(cmd, args, opts);
    });
    await injector.executeWithSecret(
      {
        type: "git",
        operation: "fetch",
        repository: REPO,
        working_directory: wd,
        timeout_ms: 10_000,
      },
      secret(),
      policy(),
      undefined,
    );
    expect(calls().map(([, , o]) => o.timeoutMs)).toEqual([10_000, 10_000, 10_000, 10_000, 6_000]);
  });

  it("fetch: a remote listing past the output cap is GIT_OPERATION_FAILED before any credential-bearing step (RX-B9-15)", async () => {
    spawnMock.mockImplementation((cmd, args, opts) => {
      const sub = gitSubcommand(args);
      if (sub === "config") return Promise.resolve({ ...OK_RESULT, truncated: true });
      if (MOCKED.includes(sub ?? "")) return Promise.resolve(OK_RESULT);
      return realSpawnCaptured(cmd, args, opts);
    });
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "fetch", repository: REPO, working_directory: wd },
          secret(),
          policy(),
          undefined,
        ),
      ErrorCode.GIT_OPERATION_FAILED,
    );
    expect(err.message).toBe(
      "Git operation failed: the working tree's remote listing exceeds the output cap",
    );
    expect(calls().map(([, a]) => gitSubcommand(a))).toEqual(["rev-parse", "config"]);
  });

  it("fetch: a failed remote lookup is returned redacted and flagged, before any credential-bearing step (RG-6)", async () => {
    const user = Buffer.from(secret()).toString("utf8").split(":")[0] as string;
    spawnMock.mockImplementation((cmd, args, opts) => {
      const sub = gitSubcommand(args);
      if (sub === "config") {
        return Promise.resolve({
          ...OK_RESULT,
          exit_code: 128,
          stderr: `fatal: unable to read config file '/home/${user}/wd/.git/config'\n`,
        });
      }
      if (MOCKED.includes(sub ?? "")) return Promise.resolve(OK_RESULT);
      return realSpawnCaptured(cmd, args, opts);
    });
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    const result = await audited.executeWithSecret(
      { type: "git", operation: "fetch", repository: REPO, working_directory: wd },
      secret(),
      policy(),
      undefined,
      "secret-1",
    );
    expect(result.exit_code).toBe(128);
    expect(JSON.stringify(result).includes(user)).toBe(false);
    expect(result.stderr.includes("[REDACTED]")).toBe(true);
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail.sanitized).toBe(true);
    expect(calls().map(([, a]) => gitSubcommand(a))).toEqual(["rev-parse", "config"]);
  });

  it("fetch: a remote whose name holds a `*` is no plain ref name, refused before any credential-bearing step", async () => {
    execFileSync(
      GIT as string,
      ["-C", wd, "config", "--rename-section", "remote.origin", "remote.a*b"],
      {
        env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG },
      },
    );
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "fetch", repository: REPO, working_directory: wd },
          secret(),
          policy(),
          undefined,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe(`the working tree's remote for ${REPO} is not a plain ref name`);
    expect(calls().map(([, a]) => gitSubcommand(a))).toEqual(["rev-parse", "config"]);
  });

  it.each([
    [
      "pull",
      [
        ["rev-parse", "none"],
        ["for-each-ref", "none"],
        ["fetch", "list"],
        ["pull", "list"],
      ],
    ],
    [
      "push",
      [
        ["rev-parse", "none"],
        ["symbolic-ref", "none"],
        ["for-each-ref", "none"],
        ["push", "list"],
      ],
    ],
    [
      "fetch",
      [
        ["rev-parse", "none"],
        ["config", "none"],
        ["for-each-ref", "none"],
        ["fetch", "list"],
        ["fetch", "list"],
      ],
    ],
  ] as const)(
    "%s: the working-tree probes carry no redaction list; the network step and the final local step carry the operation's (RG-6)",
    async (operation, plan) => {
      spawnMock.mockImplementation((cmd, args, opts) =>
        ["fetch", "push", "pull"].includes(gitSubcommand(args) ?? "")
          ? Promise.resolve(OK_RESULT)
          : realSpawnCaptured(cmd, args, opts),
      );
      await injector.executeWithSecret(
        { type: "git", operation, repository: REPO, working_directory: wd },
        secret(),
        policy(),
        undefined,
      );
      const list = JSON.stringify([TOKEN, "git-user"]);
      expect(
        calls().map(([, args, opts]) => [
          gitSubcommand(args),
          (opts.redact ?? []).length === 0
            ? "none"
            : JSON.stringify(opts.redact) === list
              ? "list"
              : "other",
        ]),
      ).toEqual(plan);
    },
  );

  it("ls-remote refuses a working_directory and a fetch requires one, before any step", async () => {
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "ls-remote", repository: REPO, working_directory: wd },
          secret(),
          policy(),
          undefined,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe("working_directory is not accepted by ls-remote");
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "fetch", repository: REPO },
          secret(),
          policy(),
          undefined,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(calls()).toEqual([]);
  });

  it("ls-remote: one credential-bearing step in an empty relay — the caller's options, `--`, the repository — and no working-tree step", async () => {
    const result = await injector.executeWithSecret(
      { type: "git", operation: "ls-remote", repository: REPO, args: ["--symref", "--heads"] },
      secret(),
      policy(),
      undefined,
    );
    expect(result).toMatchObject({ type: "git", operation: "ls-remote", exit_code: 0 });
    expect(calls()).toHaveLength(1);
    const [, args, opts] = calls()[0] as SpawnCall;
    const relay = (args.find((a) => a.startsWith("--git-dir=")) as string).slice(10);
    expect(opts.cwd).toBe(relay);
    expect(opts.env.HARPOC_GIT_PASSWORD === TOKEN).toBe(true);
    expect(args.slice(0, args.indexOf("ls-remote"))).toEqual([
      "-c",
      "http.followRedirects=false",
      "-c",
      expect.stringMatching(/^core\.hooksPath=./),
      "-c",
      "credential.helper=",
      "-c",
      "core.fsmonitor=false",
      `--git-dir=${relay}`,
    ]);
    expect(args.slice(args.indexOf("ls-remote"))).toEqual([
      "ls-remote",
      "--symref",
      "--heads",
      "--",
      REPO,
    ]);
  });
});

describeGitSsh("the fetch step plan over SSH (RX-B9-17)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);
  const SSH_REPO = "git@github.com:org/repo.git";
  const calls = () => spawnMock.mock.calls as SpawnCall[];
  let scratch: string;
  let wd: string;

  beforeEach(() => {
    scratch = mkdtempSync(join(tmpdir(), "harpoc-fetch-plan-ssh-"));
    wd = join(scratch, "wd");
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG };
    execFileSync(GIT as string, ["init", "-q", wd], { env });
    execFileSync(GIT as string, ["-C", wd, "remote", "add", "origin", SSH_REPO], { env });
    spawnMock.mockReset();
    spawnMock.mockImplementation((cmd, args, opts) =>
      MOCKED.includes(gitSubcommand(args) ?? "")
        ? Promise.resolve(OK_RESULT)
        : realSpawnCaptured(cmd, args, opts),
    );
  });

  afterEach(() => {
    rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("step 4 alone carries GIT_SSH_COMMAND and the agent socket; the probes and the local fetch carry neither", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
    };
    const result = await injector.executeWithSecret(
      { type: "git", operation: "fetch", repository: SSH_REPO, working_directory: wd },
      new Uint8Array(Buffer.from(keyPem)),
      { ...policy(), url_allowlist: [], host_allowlist: ["github.com"] },
      config,
    );
    expect(result).toMatchObject({ operation: "fetch", exit_code: 0 });
    expect(calls().map(([, a]) => gitSubcommand(a))).toEqual([
      "rev-parse",
      "config",
      "for-each-ref",
      "fetch",
      "fetch",
    ]);
    const [probe, remotes, listing, network, local] = calls();
    const [, netArgs, netOpts] = network as SpawnCall;
    expect(netArgs.some((a) => a.startsWith("--git-dir="))).toBe(true);
    expect(netOpts.env.GIT_SSH_COMMAND).toContain("IdentitiesOnly=yes");
    expect(netOpts.env.SSH_AUTH_SOCK).toBeTruthy();
    expect(netArgs.slice(netArgs.indexOf("fetch")).slice(-3)).toEqual([
      "--",
      SSH_REPO,
      "+refs/heads/*:refs/heads/*",
    ]);
    for (const step of [probe, remotes, listing, local]) {
      const [, , opts] = step as SpawnCall;
      expect(opts.cwd).toBe(wd);
      expect("GIT_SSH_COMMAND" in opts.env).toBe(false);
      expect("SSH_AUTH_SOCK" in opts.env).toBe(false);
    }
    expect((local as SpawnCall)[1].slice(-1)).toEqual(["+refs/heads/*:refs/remotes/origin/*"]);
    expect(calls().every(([, a]) => a.every((x) => !x.includes("PRIVATE KEY")))).toBe(true);
  });
});
