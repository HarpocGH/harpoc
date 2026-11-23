import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs } from "./allowlist.js";
import {
  LOCAL_STEP_VARIABLES,
  localEnvironment,
  localStepWords,
  REPOSITORY_VARIABLES,
} from "./__fixtures__/git-local-steps.js";
import { startGitSmartHttp, startRecorder } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import { gitVersionAtLeast, parseGitVersion } from "./git-injector-version.js";
import type { readGitVersion } from "./git-injector-version.js";
import { GitInjector } from "./git-injector.js";
import type { DaemonPaths } from "./local-path.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

const readVersion = vi.hoisted(() => vi.fn<typeof readGitVersion>());

vi.mock("./git-injector-version.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./git-injector-version.js")>();
  return { ...actual, readGitVersion: readVersion };
});
vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

const { spawnCaptured: realSpawnCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");
const { readGitVersion: realReadGitVersion } = await vi.importActual<
  typeof import("./git-injector-version.js")
>("./git-injector-version.js");

// On win32 the git context accepts only the native Win32-OpenSSH client, so its
// directory leads the PATH (as in git-injector.floor.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveSupportedGit();
const SSH = resolveNativeSshClient("ssh");
const WIN32 = process.platform === "win32";
const NULL_DEVICE = WIN32 ? "NUL" : "/dev/null";
const LOCAL_STEP = localStepWords(NULL_DEVICE);
const BUNDLE_GIT = resolveSupportedGit([2, 40]);
const RECENT_OBJECTS_HOOK_GIT = resolveSupportedGit([2, 42]);
const PROACTIVE_AUTH_GIT = resolveSupportedGit([2, 46]);
const NO_LAZY_FETCH_GIT = GIT !== null && honoursNoLazyFetch(GIT) ? GIT : null;

/** git 2.45.0 and later read GIT_NO_LAZY_FETCH, and so do the maintenance releases 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4 and 2.44.1. */
function honoursNoLazyFetch(git: string): boolean {
  const version = parseGitVersion(
    execFileSync(git, ["version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 20_000,
    }),
  );
  if (version === null) return false;
  const maintenance: Array<readonly [number, number, number]> = [
    [2, 39, 4],
    [2, 40, 2],
    [2, 41, 1],
    [2, 42, 2],
    [2, 43, 4],
    [2, 44, 1],
  ];
  return (
    gitVersionAtLeast(version, [2, 45]) ||
    maintenance.some(
      (floor) =>
        version.major === floor[0] &&
        version.minor === floor[1] &&
        gitVersionAtLeast(version, floor),
    )
  );
}

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SSH_HOST = "h.invalid";
const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;
const KNOWN_HOSTS: ConnectionConfig = {
  ssh: { known_hosts: [`${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
};
const SCRIPTED_SECRET = new Uint8Array(Buffer.from("git-user:local-steps-token-value"));
const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-local-steps";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const OWN_CONFIGURATION =
  "working_directory's repository configures a program or an address rewrite of its own";
const NO_PATHS: DaemonPaths = { protectedDirs: [], protectedFiles: [] };

const LOCAL_OPERATIONS = ["pull", "fetch"] as const;
type LocalOperation = (typeof LOCAL_OPERATIONS)[number];
const OPERATIONS = ["pull", "fetch", "push", "clone"] as const;
type Operation = (typeof OPERATIONS)[number];
const TRANSPORTS = ["https", "ssh"] as const;
type Transport = (typeof TRANSPORTS)[number];
type Model = "outside a daemon" | "in a daemon";
type Floor = Parameters<GitInjector["executeWithSecret"]>[6];
type SpawnCall = Parameters<typeof spawnCaptured>;

const OK_STEP: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const FORCED = [
  "-c",
  expect.stringMatching(/^core\.hooksPath=.+harpoc-git-hooks-/),
  "-c",
  "credential.helper=",
  "-c",
  "core.fsmonitor=false",
  "-c",
  "safe.bareRepository=explicit",
];

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function isNetwork(args: string[]): boolean {
  return args.some((a) => a.startsWith("--git-dir="));
}

function isListing(args: string[]): boolean {
  return (
    gitSubcommand(args) === "config" &&
    args.includes("--name-only") &&
    !args.includes("--fixed-value")
  );
}

/** A path as git prints it, with forward slashes. */
function printed(path: string): string {
  return path.replace(/\\/g, "/");
}

/** git's answer of one line each, paths as git prints them. */
function answer(...lines: string[]): string {
  return lines.map((line) => `${printed(line)}\n`).join("");
}

/** `file://` URL of a local directory, as a clone's local step names the relay. */
function fileUrl(dir: string): string {
  const p = printed(dir);
  return p.startsWith("/") ? `file://${p}` : `file:///${p}`;
}

function policy(): InjectionPolicy {
  return {
    url_allowlist: ["https://8.8.8.8/*"],
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: [SSH_HOST],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
    local_dirs: [],
  };
}

const spawnMock = vi.mocked(spawnCaptured);
let root: string;
let vaultDir: string;
let log: Mock;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-local-steps-")));
  vaultDir = join(root, "vault");
  mkdirSync(vaultDir);
  writeFileSync(join(vaultDir, "vault.db"), "");
  writeFileSync(join(vaultDir, "session.json"), "");
  mkdirSync(join(root, "tree", ".git", "objects"), { recursive: true });
  mkdirSync(join(root, "tree", ".git", "refs"));
  writeFileSync(join(root, "tree", ".git", "HEAD"), "ref: refs/heads/main\n");
  log = vi.fn();
  readVersion.mockReset();
  readVersion.mockResolvedValue({ major: 2, minor: 51, patch: 0 });
  spawnMock.mockReset();
});

afterEach(() => {
  spawnMock.mockReset();
  readVersion.mockReset();
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function floorAt(dir: string, daemon?: DaemonPaths): Floor {
  return {
    vaultFiles: [join(dir, "vault.db"), join(dir, "session.json")],
    ...(daemon !== undefined ? { daemon } : {}),
  };
}

function floorOf(model: Model): Floor {
  return floorAt(vaultDir, model === "in a daemon" ? NO_PATHS : undefined);
}

function calls(): SpawnCall[] {
  return spawnMock.mock.calls as SpawnCall[];
}

/** `run` with `values` set in the process's environment, the earlier values put back after it. */
async function withProcessEnv<T>(
  values: Record<string, string>,
  run: () => Promise<T>,
): Promise<T> {
  const before = Object.keys(values).map((name) => [name, process.env[name]] as const);
  Object.assign(process.env, values);
  try {
    return await run();
  } finally {
    for (const [name, value] of before) {
      if (value === undefined) Reflect.deleteProperty(process.env, name);
      else process.env[name] = value;
    }
  }
}

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no supported git resolves',
    );
  }
});

describe.skipIf(GIT === null)(
  "what a repository's own configuration can no longer start, scripted (skipped where no supported git resolves)",
  () => {
    const tree = () => join(root, "tree");
    const gitDir = () => join(root, "tree", ".git");
    const destination = () => join(root, "cloned");
    let sshKey: Uint8Array;

    beforeAll(() => {
      sshKey = new Uint8Array(
        Buffer.from(
          generateKeyPairSync("rsa", {
            modulusLength: 2048,
            privateKeyEncoding: { type: "pkcs1", format: "pem" },
            publicKeyEncoding: { type: "spki", format: "pem" },
          }).privateKey,
        ),
      );
    });

    function use(
      operation: Operation,
      transport: Transport = "https",
      over: { args?: string[]; envAllowlist?: string[] } = {},
    ) {
      const ssh = transport === "ssh";
      const action: GitAction = {
        type: "git",
        operation,
        repository: ssh ? SSH_REPOSITORY : HTTPS_REPOSITORY,
        working_directory: operation === "clone" ? destination() : tree(),
        ...(over.args !== undefined ? { args: over.args } : {}),
      };
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        action,
        ssh ? sshKey : SCRIPTED_SECRET,
        { ...policy(), env_allowlist: over.envAllowlist ?? [] },
        ssh ? KNOWN_HOSTS : undefined,
        "secret-1",
        undefined,
        floorAt(vaultDir),
      );
    }

    /** spawnCaptured answers by argv: the probe, a pull's top level, the push's HEAD, the fetch's remote lookup and the listing; every other step succeeds. */
    function script(): void {
      const probe = answer(
        join(gitDir(), "objects"),
        join(gitDir(), "shallow"),
        "sha1",
        gitDir(),
        gitDir(),
        "false",
      );
      spawnMock.mockImplementation((_cmd, args) => {
        let stdout = "";
        if (isListing(args)) stdout = "remote.origin.url\0remote.origin.fetch\0";
        else if (args.includes("--git-path")) stdout = probe;
        else if (args.includes("--show-toplevel")) stdout = answer(tree());
        else if (gitSubcommand(args) === "symbolic-ref") stdout = "refs/heads/main\n";
        else if (args.includes("--fixed-value")) stdout = "remote.origin.url\0";
        return Promise.resolve({ ...OK_STEP, stdout });
      });
    }

    /** The relay the last network step named. */
    function relay(): string {
      const [, args] = calls()
        .filter(([, a]) => isNetwork(a))
        .at(-1) as SpawnCall;
      return (args.find((a) => a.startsWith("--git-dir=")) as string).slice("--git-dir=".length);
    }

    function localStep(): SpawnCall {
      return calls().at(-1) as SpawnCall;
    }

    it("the local fetch's argv: the block behind the forced configuration, the vault's three switches in front of the caller's arguments", async () => {
      script();
      const result = await use("fetch", "https", { args: ["--prune"] });
      expect(result.exit_code).toBe(0);
      const [, args, opts] = localStep();
      expect(args).toEqual([
        ...FORCED,
        ...LOCAL_STEP,
        "-c",
        `url.${printed(relay())}.insteadOf=${HTTPS_REPOSITORY}`,
        "fetch",
        "--no-recurse-submodules",
        "--refmap=",
        "--upload-pack=git-upload-pack",
        "--prune",
        "--",
        HTTPS_REPOSITORY,
        "+refs/heads/*:refs/remotes/origin/*",
      ]);
      expect(opts.cwd).toBe(tree());
    });

    it("the local pull's argv: the block behind the forced configuration, the vault's two switches in front of the caller's arguments", async () => {
      script();
      const result = await use("pull", "https", { args: ["--ff-only"] });
      expect(result.exit_code).toBe(0);
      const [, args, opts] = localStep();
      expect(args).toEqual([
        ...FORCED,
        ...LOCAL_STEP,
        "-c",
        `url.${printed(relay())}.insteadOf=${HTTPS_REPOSITORY}`,
        `--work-tree=${tree()}`,
        "pull",
        "--no-recurse-submodules",
        "--upload-pack=git-upload-pack",
        "--ff-only",
        "--",
        HTTPS_REPOSITORY,
      ]);
      expect(opts.cwd).toBe(tree());
    });

    it("a clone's local step: the block behind the forced configuration, and no --upload-pack word", async () => {
      script();
      const result = await use("clone", "https", { args: ["--depth", "1"] });
      expect(result.exit_code).toBe(0);
      const [, args, opts] = localStep();
      expect(args).toEqual([
        ...FORCED,
        ...LOCAL_STEP,
        "-c",
        `url.${fileUrl(relay())}.insteadOf=${HTTPS_REPOSITORY}`,
        "clone",
        "--depth",
        "1",
        "--",
        HTTPS_REPOSITORY,
        destination(),
      ]);
      expect(args.filter((a) => a.startsWith("--upload-pack"))).toEqual([]);
      expect(opts.cwd).toBeUndefined();
    });

    it("a caller's trailing valued option cannot swallow the vault's switches: a pull with -s", async () => {
      script();
      const result = await use("pull", "https", { args: ["-s"] });
      expect(result.exit_code).toBe(0);
      const [, args] = localStep();
      const s = args.indexOf("-s");
      expect(args.slice(args.indexOf("pull"), s + 2)).toEqual([
        "pull",
        "--no-recurse-submodules",
        "--upload-pack=git-upload-pack",
        "-s",
        "--",
      ]);
    });

    const CASES = OPERATIONS.flatMap((operation) =>
      TRANSPORTS.map((transport) => [operation, transport] as const),
    );
    const HTTPS_CASES = CASES.filter(([, transport]) => transport === "https");
    const SSH_CASES = CASES.filter(([, transport]) => transport === "ssh");

    function blockWords(args: string[]): string[] {
      return args.filter(
        (a) => a === "fetch.bundleURI=" || a.startsWith("hook.") || a.startsWith("--upload-pack"),
      );
    }

    async function expectNoneOfTheBlock(operation: Operation, transport: Transport): Promise<void> {
      script();
      const result = await use(operation, transport);
      expect(result.exit_code).toBe(0);
      const all = calls();
      const local = operation === "push" ? [] : [all.at(-1) as SpawnCall];
      const others = all.filter((call) => !local.includes(call));
      expect(others.length).toBeGreaterThan(0);
      for (const [, args] of others) expect(blockWords(args)).toEqual([]);
      for (const [, args] of local) expect(args).toContain("fetch.bundleURI=");
    }

    it.each(HTTPS_CASES)(
      "the probes, the listing and the network steps carry none of the block: %s over %s",
      async (operation, transport) => {
        await expectNoneOfTheBlock(operation, transport);
      },
    );

    it.skipIf(SSH === null).each(SSH_CASES)(
      "the probes, the listing and the network steps carry none of the block: %s over %s (skipped where the native ssh client does not resolve)",
      async (operation, transport) => {
        await expectNoneOfTheBlock(operation, transport);
      },
    );

    function localEnv(): Record<string, string> {
      return {
        PATH: process.env.PATH as string,
        ...(WIN32 && process.env.SystemRoot !== undefined
          ? { SystemRoot: process.env.SystemRoot }
          : {}),
        ...localEnvironment(NULL_DEVICE),
      };
    }

    async function expectTheLocalEnvironment(
      operation: Operation,
      transport: Transport,
    ): Promise<void> {
      script();
      const result = await use(operation, transport);
      expect(result.exit_code).toBe(0);
      const local = calls().filter(([, args]) => !isNetwork(args));
      const network = calls().filter(([, args]) => isNetwork(args));
      expect(local.length).toBeGreaterThan(0);
      expect(network.length).toBeGreaterThan(0);
      for (const [, args, opts] of local) {
        expect(opts.env).toEqual(isListing(args) ? { ...localEnv(), LC_ALL: "C" } : localEnv());
        const env = opts.env as Record<string, string>;
        expect(env.GIT_ASKPASS).toBe("");
        expect(env.GIT_PROXY_COMMAND).toBe("");
      }
      for (const [, , opts] of network) {
        const env = opts.env as Record<string, string>;
        if (transport === "https") {
          expect(env.GIT_ASKPASS).toMatch(/askpass\.(cmd|sh)$/);
          expect(
            LOCAL_STEP_VARIABLES.filter((name) => name !== "GIT_ASKPASS" && name in env),
          ).toEqual([]);
        } else {
          expect(LOCAL_STEP_VARIABLES.filter((name) => name in env)).toEqual([]);
        }
      }
    }

    it.each(HTTPS_CASES)(
      "the local environment: %s over %s, every step in the caller's repository and a clone's local step (the listing also LC_ALL=C)",
      async (operation, transport) => {
        await expectTheLocalEnvironment(operation, transport);
      },
    );

    it.skipIf(SSH === null).each(SSH_CASES)(
      "the local environment: %s over %s, every step in the caller's repository and a clone's local step (the listing also LC_ALL=C; skipped where the native ssh client does not resolve)",
      async (operation, transport) => {
        await expectTheLocalEnvironment(operation, transport);
      },
    );

    const ALLOWLISTED = [
      ...REPOSITORY_VARIABLES,
      "GIT_CONFIG_KEY_0",
      "GIT_CONFIG_VALUE_0",
      "git_dir",
    ];
    const REMOVED = new Set(REPOSITORY_VARIABLES);

    function repositoryVariables(env: Record<string, string>): string[] {
      return Object.keys(env).filter(
        (name) => REMOVED.has(name.toUpperCase()) || /^GIT_CONFIG_(KEY|VALUE)_[0-9]+$/i.test(name),
      );
    }

    async function expectNoRepositoryVariable(transport: Transport): Promise<void> {
      script();
      const values = Object.fromEntries(ALLOWLISTED.map((name) => [name, `/allowlisted/${name}`]));
      const result = await withProcessEnv(values, () =>
        use("pull", transport, { envAllowlist: ALLOWLISTED }),
      );
      expect(result.exit_code).toBe(0);
      const [[, versionEnv]] = readVersion.mock.calls as [[string, Record<string, string>]];
      expect(repositoryVariables(versionEnv)).toEqual([]);
      for (const [, args, opts] of calls()) {
        const env = opts.env as Record<string, string>;
        if (transport === "ssh" && isNetwork(args)) {
          expect(repositoryVariables(env)).toEqual(["GIT_SSH_COMMAND"]);
          expect(env.GIT_SSH_COMMAND).toContain("IdentitiesOnly=yes");
        } else {
          expect(repositoryVariables(env)).toEqual([]);
        }
      }
    }

    it("git's repository variables pass no allowlist, on any step: a pull over HTTPS, the version read's environment included", async () => {
      await expectNoRepositoryVariable("https");
    });

    it.skipIf(SSH === null)(
      "git's repository variables pass no allowlist, on any step: a pull over SSH, the version read's environment included, the network step's GIT_SSH_COMMAND the vault's (skipped where the native ssh client does not resolve)",
      async () => {
        await expectNoRepositoryVariable("ssh");
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "what a repository's own configuration can no longer start, on real git against a smart-HTTP listener on 127.0.0.1 (skipped where no supported git resolves)",
  () => {
    let serverRoot: string;
    let srv: string;
    let server: Listener;
    let gitEnv: NodeJS.ProcessEnv;
    let remotes = 0;

    function git(cwd: string, ...args: string[]): string {
      return execFileSync(GIT as string, args, {
        cwd,
        env: gitEnv,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    }

    function gitWithInput(cwd: string, input: string | Buffer, ...args: string[]): string {
      return execFileSync(GIT as string, args, {
        cwd,
        env: gitEnv,
        encoding: "utf8",
        input,
        stdio: ["pipe", "pipe", "pipe"],
      });
    }

    const url = (name: string) => `http://127.0.0.1:${String(server.port)}/${name}`;
    const markers = () => join(root, "m");

    /** An executable script, one shell line that creates the empty marker file `name`; its path as git reads it, which no shell splits. */
    function program(name: string): string {
      const bin = join(root, "bin");
      mkdirSync(bin, { recursive: true });
      const script = join(bin, name);
      expect(/^[\w./:~-]+$/.test(printed(script))).toBe(true);
      writeFileSync(script, `#!/bin/sh\n: > '${printed(join(markers(), name))}'\n`, {
        mode: 0o755,
      });
      return printed(script);
    }

    /** The local step was spawned: a call that carries the block. */
    function expectTheLocalStep(): void {
      expect(calls().some(([, args]) => args.includes("fetch.bundleURI="))).toBe(true);
    }

    function serve(
      action: Omit<GitAction, "type">,
      model: Model = "outside a daemon",
      envAllowlist: string[] = [],
    ) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", ...action },
        SERVED_SECRET,
        {
          ...policy(),
          url_allowlist: [`http://127.0.0.1:${String(server.port)}/*`],
          env_allowlist: envAllowlist,
        },
        undefined,
        "secret-1",
        undefined,
        floorOf(model),
      );
    }

    /** A commit in `dir` that writes `n` to `file`; its id. */
    function commit(dir: string, n: string, file = "top.txt"): string {
      writeFileSync(join(dir, file), `${n}\n`);
      git(dir, "add", file);
      git(dir, "commit", "-q", "-m", `c${n}`);
      return git(dir, "rev-parse", "HEAD").trim();
    }

    /** A bare repository the listener serves, its `main` the first commit of `seed`. */
    function remote(): { name: string; bare: string; seed: string } {
      remotes += 1;
      const name = `repo-${String(remotes)}.git`;
      const seed = join(root, `seed-${String(remotes)}`);
      git(root, "init", "-q", "-b", "main", seed);
      commit(seed, "1");
      const bare = join(srv, name);
      git(root, "clone", "-q", "--bare", seed, bare);
      return { name, bare, seed };
    }

    /** The remote's next commit, pushed straight into its bare repository; its id. */
    function advance(seed: string, bare: string, n: string): string {
      const head = commit(seed, n);
      git(seed, "push", "-q", bare, "HEAD:refs/heads/main");
      return head;
    }

    /** A work tree cloned from `bare`, its origin the listener's address, with an identity of its own. */
    function cloneOf(bare: string, name: string): string {
      const wt = join(root, "wt");
      git(root, "clone", "-q", bare, wt);
      git(wt, "config", "remote.origin.url", url(name));
      git(wt, "config", "user.name", "harpoc-test");
      git(wt, "config", "user.email", "test@example.com");
      return wt;
    }

    /** A work tree cloned from the remote; the remote then moves on. */
    function workTree(): { wt: string; name: string; bare: string; seed: string; next: string } {
      const { name, bare, seed } = remote();
      const wt = cloneOf(bare, name);
      const next = advance(seed, bare, "2");
      return { wt, name, bare, seed, next };
    }

    /** A work tree with an initialised submodule `sm`; then the submodule's remote and the superproject's pointer move on. */
    function withSubmodule(): { wt: string; name: string; bare: string; next: string } {
      const { name, bare, seed } = remote();
      const smSeed = join(root, "sm-seed");
      git(root, "init", "-q", "-b", "main", smSeed);
      commit(smSeed, "s1", "s.txt");
      const smBare = join(root, "sm.git");
      git(root, "clone", "-q", "--bare", smSeed, smBare);
      git(
        seed,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        printed(smBare),
        "sm",
      );
      git(seed, "commit", "-q", "-m", "add sm");
      git(seed, "push", "-q", bare, "HEAD:refs/heads/main");
      const wt = cloneOf(bare, name);
      git(wt, "-c", "protocol.file.allow=always", "submodule", "update", "-q", "--init");
      commit(smSeed, "s2", "s.txt");
      git(smSeed, "push", "-q", smBare, "HEAD:refs/heads/main");
      git(join(seed, "sm"), "pull", "-q", "origin", "main");
      git(seed, "add", "sm");
      git(seed, "commit", "-q", "-m", "move sm");
      git(seed, "push", "-q", bare, "HEAD:refs/heads/main");
      return { wt, name, bare, next: git(seed, "rev-parse", "HEAD").trim() };
    }

    /** A port on 127.0.0.1 nothing listens on. */
    async function closedPort(): Promise<number> {
      const probe = createServer();
      await new Promise<void>((done) => probe.listen(0, "127.0.0.1", done));
      const { port } = probe.address() as AddressInfo;
      await new Promise<void>((done) => probe.close(() => done()));
      return port;
    }

    beforeAll(async () => {
      serverRoot = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-local-steps-srv-")));
      const emptyConfig = join(serverRoot, "empty.gitconfig");
      writeFileSync(emptyConfig, "");
      gitEnv = {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: emptyConfig,
        GIT_TERMINAL_PROMPT: "0",
        GIT_AUTHOR_NAME: "harpoc-test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "harpoc-test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
      srv = join(serverRoot, "srv");
      mkdirSync(srv);
      server = await startGitSmartHttp({
        git: GIT as string,
        projectRoot: srv,
        user: SERVER_USER,
        token: SERVER_TOKEN,
        env: gitEnv,
      });
    });

    beforeEach(() => {
      mkdirSync(markers());
      spawnMock.mockImplementation(realSpawnCaptured);
      readVersion.mockImplementation(realReadGitVersion);
    });

    afterAll(async () => {
      try {
        if (server !== undefined) await server.close();
      } finally {
        if (serverRoot !== undefined)
          rmSync(serverRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    });

    /** A work tree whose remote moved on, with `plant` applied to it; the tree and the address. */
    function planted(
      plant: (tree: { wt: string; address: string; bare: string }) => void,
    ): () => { wt: string; address: string } {
      return () => {
        const { wt, name, bare } = workTree();
        plant({ wt, address: url(name), bare });
        return { wt, address: url(name) };
      };
    }

    /** Two packs more than the clone's and an unreachable object from 2020: a fetch's or a merge's maintenance repacks. */
    function plantMaintenance(wt: string): void {
      for (const object of ["HEAD:top.txt", "HEAD^{tree}"]) {
        gitWithInput(
          wt,
          `${git(wt, "rev-parse", object).trim()}\n`,
          "pack-objects",
          "-q",
          join(wt, ".git", "objects", "pack", "pack"),
        );
      }
      const unreachable = gitWithInput(
        wt,
        "harpoc unreachable object\n",
        "hash-object",
        "-w",
        "--stdin",
      ).trim();
      const old = new Date("2020-01-01T00:00:00Z");
      utimesSync(
        join(wt, ".git", "objects", unreachable.slice(0, 2), unreachable.slice(2)),
        old,
        old,
      );
      git(wt, "config", "gc.autoPackLimit", "1");
      git(wt, "config", "gc.autoDetach", "false");
      git(wt, "config", "maintenance.autoDetach", "false");
      git(wt, "config", "maintenance.auto", "true");
    }

    const STARTS_NOTHING: ReadonlyArray<
      readonly [string, readonly LocalOperation[], () => { wt: string; address: string }]
    > = [
      [
        "core.alternateRefsCommand with an alternates file",
        LOCAL_OPERATIONS,
        planted(({ wt, bare }) => {
          mkdirSync(join(wt, ".git", "objects", "info"), { recursive: true });
          writeFileSync(
            join(wt, ".git", "objects", "info", "alternates"),
            `${printed(join(bare, "objects"))}\n`,
          );
          git(wt, "config", "core.alternateRefsCommand", program("alt"));
        }),
      ],
      [
        "remote.<address>.uploadpack",
        LOCAL_OPERATIONS,
        planted(({ wt, address }) =>
          git(wt, "config", `remote.${address}.uploadpack`, program("upl")),
        ),
      ],
      [
        "protocol.ext.allow and remote.<address>.url = ext::…",
        LOCAL_OPERATIONS,
        planted(({ wt, address }) => {
          git(wt, "config", "protocol.ext.allow", "always");
          git(wt, "config", `remote.${address}.url`, `ext::${program("ext")}`);
        }),
      ],
      [
        "protocol.ext.allow and url.ext::….insteadOf = <address>",
        LOCAL_OPERATIONS,
        planted(({ wt, address }) => {
          git(wt, "config", "protocol.ext.allow", "always");
          git(wt, "config", `url.ext::${program("exti")}.insteadOf`, address);
        }),
      ],
      [
        "protocol.ssh.allow and core.sshCommand",
        LOCAL_OPERATIONS,
        planted(({ wt, address }) => {
          git(wt, "config", "protocol.ssh.allow", "always");
          git(wt, "config", "core.sshCommand", program("ssh"));
          git(wt, "config", `remote.${address}.url`, "ssh://h.invalid/x.git");
        }),
      ],
      [
        "protocol.git.allow and core.gitProxy",
        LOCAL_OPERATIONS,
        planted(({ wt, address }) => {
          git(wt, "config", "protocol.git.allow", "always");
          git(wt, "config", "core.gitProxy", program("proxy"));
          git(wt, "config", `remote.${address}.url`, "git://h.invalid/x.git");
        }),
      ],
      [
        "remote.<address>.vcs = ext",
        LOCAL_OPERATIONS,
        planted(({ wt, address }) => {
          git(wt, "config", "protocol.ext.allow", "always");
          git(wt, "config", `remote.${address}.vcs`, "ext");
          git(wt, "config", `remote.${address}.url`, program("vcs"));
        }),
      ],
      [
        "core.attributesFile naming a file that names a smudge filter",
        ["pull"],
        planted(({ wt }) => {
          const attributes = join(root, "planted-attributes");
          writeFileSync(attributes, "* filter=ha\n");
          git(wt, "config", "core.attributesFile", printed(attributes));
          git(wt, "config", "filter.ha.smudge", program("smudge"));
        }),
      ],
      [
        "pull.rebase = interactive with sequence.editor",
        ["pull"],
        planted(({ wt }) => {
          commit(wt, "local", "local.txt");
          git(wt, "config", "pull.rebase", "interactive");
          git(wt, "config", "sequence.editor", program("seq"));
        }),
      ],
      [
        "fetch.recurseSubmodules = true with a submodule whose own config names an uploadpack",
        ["pull"],
        () => {
          const { wt, name } = withSubmodule();
          git(wt, "config", "fetch.recurseSubmodules", "true");
          git(
            wt,
            "config",
            "-f",
            join(wt, ".git", "modules", "sm", "config"),
            "remote.origin.uploadpack",
            program("subupl"),
          );
          return { wt, address: url(name) };
        },
      ],
    ];

    it.each(
      STARTS_NOTHING.flatMap(([label, operations, setUp]) =>
        operations.map((operation) => [operation, label, setUp] as const),
      ),
    )(
      "a repository's own configuration starts nothing in a fetch or a pull: %s, %s",
      async (operation, _label, setUp) => {
        const { wt, address } = setUp();
        await serve({ operation, repository: address, working_directory: wt });
        expectTheLocalStep();
        expect(readdirSync(markers())).toEqual([]);
      },
      120_000,
    );

    it.skipIf(RECENT_OBJECTS_HOOK_GIT === null).each(LOCAL_OPERATIONS)(
      "a repository's own configuration starts nothing in a fetch or a pull: %s, gc.recentObjectsHook with maintenance.auto = true and an old unreachable object (skipped below git 2.42, which has no gc.recentObjectsHook)",
      async (operation) => {
        const { wt, name } = workTree();
        plantMaintenance(wt);
        git(wt, "config", "gc.recentObjectsHook", program("gc"));
        await serve({ operation, repository: url(name), working_directory: wt });
        expectTheLocalStep();
        expect(readdirSync(markers())).toEqual([]);
      },
      120_000,
    );

    it.skipIf(BUNDLE_GIT === null).each(LOCAL_OPERATIONS)(
      "a bundle the repository names is not fetched: %s, fetch.bundleURI naming a bundle file of an older commit leaves no ref under refs/bundles/ (skipped below git 2.40, which has no fetch.bundleURI)",
      async (operation) => {
        const { wt, name, seed } = workTree();
        git(seed, "branch", "older", "HEAD~1");
        const bundle = join(root, "older.bundle");
        git(seed, "bundle", "create", "-q", bundle, "older");
        git(wt, "config", "fetch.bundleURI", printed(bundle));
        await serve({ operation, repository: url(name), working_directory: wt });
        expectTheLocalStep();
        expect(git(wt, "for-each-ref", "refs/bundles/")).toBe("");
      },
      120_000,
    );

    it.skipIf(BUNDLE_GIT === null).each(LOCAL_OPERATIONS)(
      "a bundle the repository names is not fetched: %s, fetch.bundleURI naming an http address of a listener of the row's own, protocol.http.allow = always beside it, and the listener sees no request (skipped below git 2.40, which has no fetch.bundleURI)",
      async (operation) => {
        const { wt, name } = workTree();
        const bundles = await startRecorder();
        try {
          git(wt, "config", "protocol.http.allow", "always");
          git(wt, "config", "fetch.bundleURI", `http://127.0.0.1:${String(bundles.port)}/x.bundle`);
          await serve({ operation, repository: url(name), working_directory: wt });
          expectTheLocalStep();
          expect(bundles.requests).toEqual([]);
        } finally {
          await bundles.close();
        }
      },
      120_000,
    );

    it.skipIf(PROACTIVE_AUTH_GIT === null).each(LOCAL_OPERATIONS)(
      "core.askPass is not run: %s, fetch.bundleURI naming a user at a closed port with http.proactiveAuth (skipped below git 2.46, which has no http.proactiveAuth)",
      async (operation) => {
        const { wt, name } = workTree();
        const port = await closedPort();
        git(wt, "config", "fetch.bundleURI", `http://u@127.0.0.1:${String(port)}/x.bundle`);
        git(wt, "config", "http.proactiveAuth", "basic");
        git(wt, "config", "core.askPass", program("askpass"));
        await serve({ operation, repository: url(name), working_directory: wt });
        expectTheLocalStep();
        expect(readdirSync(markers())).toEqual([]);
      },
      120_000,
    );

    it.skipIf(NO_LAZY_FETCH_GIT === null)(
      "a partial clone's pull that needs a missing object fails and starts nothing (skipped where git does not read GIT_NO_LAZY_FETCH: below 2.45 but for the maintenance releases from 2.39.4)",
      async () => {
        const { wt, name, bare } = workTree();
        const blob = git(wt, "rev-parse", "HEAD:top.txt").trim();
        const pack = join(wt, ".git", "objects", "pack");
        const moved = join(root, "packs");
        mkdirSync(moved);
        for (const file of readdirSync(pack)) renameSync(join(pack, file), join(moved, file));
        for (const file of readdirSync(moved).filter((f) => f.endsWith(".pack"))) {
          gitWithInput(wt, readFileSync(join(moved, file)), "unpack-objects", "-q");
        }
        rmSync(join(wt, ".git", "objects", blob.slice(0, 2), blob.slice(2)), {
          force: true,
          maxRetries: 5,
          retryDelay: 100,
        });
        git(wt, "config", "core.repositoryformatversion", "1");
        git(wt, "config", "extensions.partialClone", "pz");
        git(wt, "config", "remote.pz.url", printed(bare));
        git(wt, "config", "remote.pz.promisor", "true");
        git(wt, "config", "remote.pz.uploadpack", program("lazy"));
        const result = await serve({
          operation: "pull",
          repository: url(name),
          working_directory: wt,
        });
        expectTheLocalStep();
        expect(readdirSync(markers())).toEqual([]);
        expect(result.exit_code).not.toBe(0);
      },
      120_000,
    );

    it("a pull fetches and updates no submodule: submodule.recurse = true, the submodule's HEAD as before", async () => {
      const { wt, name, next } = withSubmodule();
      git(wt, "config", "submodule.recurse", "true");
      const before = git(join(wt, "sm"), "rev-parse", "HEAD").trim();
      const result = await serve({
        operation: "pull",
        repository: url(name),
        working_directory: wt,
      });
      expect(result.exit_code, result.stderr).toBe(0);
      expect(git(wt, "rev-parse", "HEAD").trim()).toBe(next);
      expect(git(join(wt, "sm"), "rev-parse", "HEAD").trim()).toBe(before);
    }, 120_000);

    const CLEAN: ReadonlyArray<readonly [string, () => Promise<void>]> = [
      [
        "a fetch",
        async () => {
          const { wt, name, next } = workTree();
          const result = await serve({
            operation: "fetch",
            repository: url(name),
            working_directory: wt,
          });
          expect(result.exit_code, result.stderr).toBe(0);
          expect(git(wt, "rev-parse", "refs/remotes/origin/main").trim()).toBe(next);
        },
      ],
      [
        "a fast-forward pull",
        async () => {
          const { wt, name, next } = workTree();
          const result = await serve({
            operation: "pull",
            repository: url(name),
            working_directory: wt,
          });
          expect(result.exit_code, result.stderr).toBe(0);
          expect(git(wt, "rev-parse", "HEAD").trim()).toBe(next);
        },
      ],
      [
        "a merging pull",
        async () => {
          const { wt, name, next } = workTree();
          commit(wt, "local", "local.txt");
          const result = await serve({
            operation: "pull",
            repository: url(name),
            working_directory: wt,
            args: ["--no-rebase"],
          });
          expect(result.exit_code, result.stderr).toBe(0);
          expect(git(wt, "rev-parse", "HEAD^2").trim()).toBe(next);
        },
      ],
      [
        "a push",
        async () => {
          const { name, bare } = remote();
          const wt = cloneOf(bare, name);
          const head = commit(wt, "pushed", "pushed.txt");
          const result = await serve({
            operation: "push",
            repository: url(name),
            working_directory: wt,
          });
          expect(result.exit_code, result.stderr).toBe(0);
          expect(git(bare, "rev-parse", "refs/heads/main").trim()).toBe(head);
        },
      ],
      [
        "a clone",
        async () => {
          const { name, bare } = remote();
          const dest = join(root, "cloned");
          const result = await serve({
            operation: "clone",
            repository: url(name),
            working_directory: dest,
          });
          expect(result.exit_code, result.stderr).toBe(0);
          expect(git(dest, "rev-parse", "HEAD").trim()).toBe(
            git(bare, "rev-parse", "refs/heads/main").trim(),
          );
        },
      ],
    ];

    it.each(CLEAN)(
      "a clean tree keeps working with the block and the variables: %s",
      async (_label, run) => {
        await run();
        expect(readdirSync(markers())).toEqual([]);
      },
      120_000,
    );

    it("an allowlisted variable does not blind the listing: in a daemon, GIT_CONFIG naming an empty file allowlisted, core.sshCommand planted, a fetch is refused", async () => {
      const { wt, name } = workTree();
      git(wt, "config", "core.sshCommand", program("ssh"));
      const empty = join(root, "empty.gitconfig");
      writeFileSync(empty, "");
      const err = await withProcessEnv({ GIT_CONFIG: empty }, () =>
        expectVaultError(
          () =>
            serve(
              { operation: "fetch", repository: url(name), working_directory: wt },
              "in a daemon",
              ["GIT_CONFIG"],
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        ),
      );
      expect(err.message).toBe(OWN_CONFIGURATION);
    }, 120_000);

    it("an allowlisted variable does not blind the listing: in a daemon, GIT_DIR naming a clean repository allowlisted, core.sshCommand planted, a fetch is refused", async () => {
      const { wt, name } = workTree();
      git(wt, "config", "core.sshCommand", program("ssh"));
      const clean = join(root, "clean");
      git(root, "init", "-q", "-b", "main", clean);
      const err = await withProcessEnv({ GIT_DIR: join(clean, ".git") }, () =>
        expectVaultError(
          () =>
            serve(
              { operation: "fetch", repository: url(name), working_directory: wt },
              "in a daemon",
              ["GIT_DIR"],
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        ),
      );
      expect(err.message).toBe(OWN_CONFIGURATION);
    }, 120_000);
  },
);
