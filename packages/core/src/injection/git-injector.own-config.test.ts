import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs } from "./allowlist.js";
import { localStepWords } from "./__fixtures__/git-local-steps.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import { OWN_CONFIG_PATTERN } from "./git-injector-local-steps.js";
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
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, lstat: vi.fn(actual.lstat) };
});

const actualFs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
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
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__");
const NON_UTF8_NAMES = !WIN32 && takesNonUtf8Name();

/** Whether the temporary directory's file system, where every fixture of this suite lies, takes a name that is no UTF-8. */
function takesNonUtf8Name(): boolean {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-git-own-config-probe-"));
  try {
    writeFileSync(Buffer.concat([Buffer.from(join(dir, "e")), Buffer.from([0xff])]), "");
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SSH_HOST = "h.invalid";
const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;
const LEGACY_REPOSITORY = `git@${SSH_HOST}:remote.git`;
const BACKSLASH_REPOSITORY = `git@${SSH_HOST}:a\\b.git`;
const KNOWN_HOSTS: ConnectionConfig = {
  ssh: { known_hosts: [`${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
};
const PINNED_CA: ConnectionConfig = { git: { ca_pem: "unused-ca-pem" } };
const SCRIPTED_SECRET = new Uint8Array(Buffer.from("git-user:own-config-token-value"));
const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-own-config";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const OWN_CONFIGURATION =
  "working_directory's repository configures a program or an address rewrite of its own";
const UNLISTED = "Git operation failed: the repository's configuration could not be listed";
const NO_PATHS: DaemonPaths = { protectedDirs: [], protectedFiles: [] };
const NO_HIT_LISTING = "remote.origin.url\0remote.origin.fetch\0";

const LOCAL_OPERATIONS = ["pull", "fetch"] as const;
type LocalOperation = (typeof LOCAL_OPERATIONS)[number];
type Operation = LocalOperation | "push";
const MODELS = ["outside a daemon", "in a daemon"] as const;
type Model = (typeof MODELS)[number];
type Floor = Parameters<GitInjector["executeWithSecret"]>[6];
type SpawnCall = Parameters<typeof spawnCaptured>;

const BEFORE_THE_LISTING: Record<LocalOperation, string[]> = {
  pull: ["rev-parse", "rev-parse", "for-each-ref", "fetch"],
  fetch: ["rev-parse", "config", "for-each-ref", "fetch"],
};

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
const lstatMock = vi.mocked(lstat);
const unreadable = new Map<string, string>();
let root: string;
let vaultDir: string;
let log: Mock;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-own-config-")));
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
  lstatMock.mockImplementation(async (path, options) => {
    const code = unreadable.get(String(path));
    if (code !== undefined) {
      throw Object.assign(new Error(`${code}: lstat`), { code });
    }
    return actualFs.lstat(path, options);
  });
});

afterEach(() => {
  unreadable.clear();
  lstatMock.mockReset();
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

function steps(): Array<string | undefined> {
  return calls().map(([, args]) => gitSubcommand(args));
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

function failedRow(
  operation: Operation,
  error: string,
  over: Record<string, unknown> = { transport: "https" },
) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: {
      context: "git",
      operation,
      ...over,
      error,
      network_isolation: false,
      fs_isolation: false,
    },
    success: false,
  };
}

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no supported git resolves',
    );
  }
});

describe.skipIf(GIT === null)(
  "the repository's own configuration, read before the local step obeys it, scripted (skipped where no supported git resolves)",
  () => {
    const tree = () => join(root, "tree");
    const gitDir = () => join(root, "tree", ".git");
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
      model: Model,
      repository: string = HTTPS_REPOSITORY,
      connection: ConnectionConfig | undefined = undefined,
      envAllowlist: string[] = [],
    ) {
      const ssh = !repository.startsWith("https://");
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository, working_directory: tree() },
        ssh ? sshKey : SCRIPTED_SECRET,
        { ...policy(), env_allowlist: envAllowlist },
        ssh ? KNOWN_HOSTS : connection,
        "secret-1",
        undefined,
        floorOf(model),
      );
    }

    function probeAnswer(paths: { gitDir?: string; commonDir?: string } = {}): string {
      const common = paths.commonDir ?? gitDir();
      return answer(
        join(common, "objects"),
        join(common, "shallow"),
        "sha1",
        paths.gitDir ?? gitDir(),
        common,
        "false",
      );
    }

    /** spawnCaptured answers by argv: the probe, a pull's top level, the push's HEAD, the fetch's remote lookup and the listing; every other step succeeds. */
    function script(listing: Partial<SpawnCapturedResult> = {}, probe = probeAnswer()): void {
      spawnMock.mockImplementation((_cmd, args) => {
        if (isListing(args)) {
          return Promise.resolve({ ...OK_STEP, stdout: NO_HIT_LISTING, ...listing });
        }
        let stdout = "";
        if (args.includes("--git-path")) stdout = probe;
        else if (args.includes("--show-toplevel")) stdout = answer(tree());
        else if (gitSubcommand(args) === "symbolic-ref") stdout = "refs/heads/main\n";
        else if (args.includes("--fixed-value")) stdout = "remote.origin.url\0";
        return Promise.resolve({ ...OK_STEP, stdout });
      });
    }

    function expectServed(operation: LocalOperation): void {
      expect(steps()).toEqual([...BEFORE_THE_LISTING[operation], "config", operation]);
      const [, last] = calls().at(-1) as SpawnCall;
      expect(isNetwork(last)).toBe(false);
    }

    async function expectRefused(
      operation: LocalOperation,
      call: () => Promise<unknown>,
      over: Record<string, unknown> = { transport: "https" },
    ): Promise<void> {
      const err = await expectVaultError(call, ErrorCode.INVALID_GIT_CONFIG);
      expect(err.message).toBe(OWN_CONFIGURATION);
      expect(log.mock.calls).toEqual([[failedRow(operation, "INVALID_GIT_CONFIG", over)]]);
      expect(steps()).toEqual([...BEFORE_THE_LISTING[operation], "config"]);
    }

    it.each(LOCAL_OPERATIONS)(
      "the listing's argv and place: %s lists the repository's configuration after the network fetch, in the top, on the local environment",
      async (operation) => {
        script();
        const result = await use(operation, "outside a daemon");
        expect(result.exit_code).toBe(0);
        expectServed(operation);
        const [, args, opts] = calls()[4] as SpawnCall;
        expect(args).toEqual([
          ...FORCED,
          "config",
          "-z",
          "--name-only",
          "--get-regexp",
          "--end-of-options",
          OWN_CONFIG_PATTERN,
        ]);
        expect(opts.cwd).toBe(tree());
        const [, , probeOpts] = calls()[0] as SpawnCall;
        expect(opts.env).toEqual({ ...probeOpts.env, LC_ALL: "C" });
        const env = opts.env as Record<string, string>;
        expect(
          Object.keys(env).filter(
            (name) => name.startsWith("HARPOC_GIT_") || name === "SSH_AUTH_SOCK",
          ),
        ).toEqual([]);
        expect(env.GIT_ASKPASS).toBe("");
      },
    );

    it.each(LOCAL_OPERATIONS)(
      "the listing carries none of the local step's keys: %s, its argv holds no word of the block beyond the forced configuration",
      async (operation) => {
        script();
        const result = await use(operation, "outside a daemon");
        expect(result.exit_code).toBe(0);
        const [, listing] = calls().find(([, args]) => isListing(args)) as SpawnCall;
        const block = new Set(localStepWords(NULL_DEVICE).filter((word) => word !== "-c"));
        expect(listing.filter((word) => block.has(word))).toEqual([]);
      },
    );

    it.each(LOCAL_OPERATIONS)(
      "with an empty allowlist no step but the listing holds LC_ALL: %s, its probes, its network step and its local step",
      async (operation) => {
        script();
        const result = await use(operation, "outside a daemon");
        expect(result.exit_code).toBe(0);
        expectServed(operation);
        expect(
          calls()
            .filter(([, , opts]) => "LC_ALL" in (opts.env as object))
            .map(([, args]) => (isListing(args) ? "the listing" : gitSubcommand(args))),
        ).toEqual(["the listing"]);
      },
    );

    const UTF8_LOCALE = { LC_ALL: "C.UTF-8", LANG: "C.UTF-8", LC_CTYPE: "C.UTF-8" };

    it.each(LOCAL_OPERATIONS)(
      "the listing alone runs in the C locale: %s with LC_ALL, LANG and LC_CTYPE allowlisted and C.UTF-8 in the process",
      async (operation) => {
        script();
        const result = await withProcessEnv(UTF8_LOCALE, () =>
          use(operation, "outside a daemon", HTTPS_REPOSITORY, undefined, Object.keys(UTF8_LOCALE)),
        );
        expect(result.exit_code).toBe(0);
        expectServed(operation);
        const inTheTree = calls().filter(([, args]) => !isNetwork(args));
        const [listing, ...others] = [
          ...inTheTree.filter(([, args]) => isListing(args)),
          ...inTheTree.filter(([, args]) => !isListing(args)),
        ] as [SpawnCall, ...SpawnCall[]];
        const [, , probeOpts] = calls()[0] as SpawnCall;
        expect(listing[2].env).toEqual({ ...probeOpts.env, LC_ALL: "C" });
        expect(others).toHaveLength(4);
        for (const [, , opts] of others) {
          const env = opts.env as Record<string, string>;
          expect([env.LC_ALL, env.LANG, env.LC_CTYPE]).toEqual(Object.values(UTF8_LOCALE));
        }
      },
    );

    // Windows reads an environment variable's name in any case.
    it.runIf(WIN32)(
      "an allowlisted lc_all does not stand beside the listing's LC_ALL on win32",
      async () => {
        script();
        const result = await withProcessEnv({ LC_ALL: "C.UTF-8" }, () =>
          use("fetch", "outside a daemon", HTTPS_REPOSITORY, undefined, ["lc_all"]),
        );
        expect(result.exit_code).toBe(0);
        const [, , listingOpts] = calls().find(([, args]) => isListing(args)) as SpawnCall;
        const [, , probeOpts] = calls()[0] as SpawnCall;
        expect((probeOpts.env as Record<string, string>).lc_all).toBe("C.UTF-8");
        expect(
          Object.entries(listingOpts.env as Record<string, string>).filter(
            ([name]) => name.toUpperCase() === "LC_ALL",
          ),
        ).toEqual([["LC_ALL", "C"]]);
      },
    );

    it.each(MODELS)(
      "a push runs no second config and no listing, a hook command in its configuration or not: %s",
      async (model) => {
        script({ stdout: "hook.x.command\0core.sshcommand\0" });
        const result = await use("push", model);
        expect(result.exit_code).toBe(0);
        expect(steps()).toEqual(["rev-parse", "symbolic-ref", "for-each-ref", "push"]);
        expect(calls().filter(([, args]) => isListing(args))).toEqual([]);
      },
    );

    const BOTH_MODELS = LOCAL_OPERATIONS.flatMap((operation) =>
      MODELS.map((model) => [operation, model] as const),
    );

    it.each(BOTH_MODELS)(
      "a hook command refuses a pull and a fetch in both models: %s %s",
      async (operation, model) => {
        script({ stdout: "remote.origin.url\0hook.x.command\0" });
        await expectRefused(operation, () => use(operation, model));
      },
    );

    it.each(BOTH_MODELS)(
      "a remote group named like the address refuses a pull and a fetch in both models: %s %s",
      async (operation, model) => {
        script({
          stdout: `remote.origin.url\0remote.r1.url\0remote.r2.url\0remotes.${HTTPS_REPOSITORY}\0`,
        });
        await expectRefused(operation, () => use(operation, model));
      },
    );

    it.each(BOTH_MODELS)(
      "a remote group under another name is no hit: %s %s",
      async (operation, model) => {
        script({
          stdout: `remote.origin.url\0remotes.default\0remotes.other.git\0remotes.${HTTPS_REPOSITORY}.git\0`,
        });
        const result = await use(operation, model);
        expect(result.exit_code).toBe(0);
        expectServed(operation);
      },
    );

    const DAEMON_LIST = [
      "core.sshcommand",
      "filter.f.smudge",
      "url.x.insteadof",
      `remote.${HTTPS_REPOSITORY}.url`,
      "fetch.bundleuri",
      "extensions.partialclone",
    ];

    it.each(
      LOCAL_OPERATIONS.flatMap((operation) =>
        DAEMON_LIST.map((name) => [operation, name] as const),
      ),
    )(
      "the daemon's list refuses in a daemon and is served outside one: %s, %s",
      async (operation, name) => {
        script({ stdout: `remote.origin.url\0${name}\0` });
        await expectRefused(operation, () => use(operation, "in a daemon"));

        spawnMock.mockClear();
        log.mockClear();
        const result = await use(operation, "outside a daemon");
        expect(result.exit_code).toBe(0);
        expectServed(operation);
      },
    );

    const NOTHING_MATCHED: ReadonlyArray<readonly [string, Partial<SpawnCapturedResult>]> = [
      ["exit 1 with an empty output", { exit_code: 1, stdout: "" }],
      ["exit 0 with the tree's own remote", { exit_code: 0, stdout: NO_HIT_LISTING }],
    ];

    it.each(
      NOTHING_MATCHED.flatMap(([how, listing]) =>
        BOTH_MODELS.map(([operation, model]) => [how, operation, model, listing] as const),
      ),
    )("nothing matched is no hit: %s, %s %s", async (_how, operation, model, listing) => {
      script(listing);
      const result = await use(operation, model);
      expect(result.exit_code).toBe(0);
      expectServed(operation);
    });

    const SECRET_PATH = "SECRET-PATH";
    const NAMING_A_PATH = `fatal: bad config line 3 in file /srv/${SECRET_PATH}/config\n`;
    const FAILED_LISTINGS: ReadonlyArray<readonly [string, Partial<SpawnCapturedResult>]> = [
      ["exit 128 naming a path", { exit_code: 128, stdout: "", stderr: NAMING_A_PATH }],
      ["exit 1 with an output", { exit_code: 1, stdout: "x\0", stderr: NAMING_A_PATH }],
      [
        "cut by the output cap on exit 0",
        { exit_code: 0, truncated: true, stdout: NO_HIT_LISTING, stderr: NAMING_A_PATH },
      ],
      [
        "timed out",
        {
          exit_code: null,
          timed_out: true,
          signal: "SIGKILL",
          stdout: NO_HIT_LISTING,
          stderr: NAMING_A_PATH,
        },
      ],
      [
        "failed to spawn",
        { exit_code: null, spawn_failed: true, stdout: "", stderr: NAMING_A_PATH },
      ],
    ];

    it.each(
      FAILED_LISTINGS.flatMap(([how, listing]) =>
        LOCAL_OPERATIONS.map((operation) => [how, operation, listing] as const),
      ),
    )(
      "a listing that fails refuses and returns nothing of its output: %s, %s",
      async (_how, operation, listing) => {
        script(listing);
        const err = await expectVaultError(
          () => use(operation, "outside a daemon"),
          ErrorCode.GIT_OPERATION_FAILED,
        );
        expect(err.message.includes(SECRET_PATH)).toBe(false);
        expect(JSON.stringify(err).includes(SECRET_PATH)).toBe(false);
        expect(JSON.stringify(log.mock.calls).includes(SECRET_PATH)).toBe(false);
        expect(err.message).toBe(UNLISTED);
        expect(log.mock.calls).toEqual([[failedRow(operation, "GIT_OPERATION_FAILED")]]);
        expect(steps()).toEqual([...BEFORE_THE_LISTING[operation], "config"]);
      },
    );

    it.each(LOCAL_OPERATIONS)(
      "with a CA pinned the refusal's row carries ca_pinned: %s",
      async (operation) => {
        script({ stdout: "hook.x.command\0" });
        await expectRefused(
          operation,
          () => use(operation, "outside a daemon", HTTPS_REPOSITORY, PINNED_CA),
          { transport: "https", ca_pinned: true },
        );
      },
    );

    it.skipIf(SSH === null).each(LOCAL_OPERATIONS)(
      "over SSH the row names the host, and the listing's environment holds no agent socket: %s (skipped where the native ssh client does not resolve)",
      async (operation) => {
        script({ stdout: "hook.x.command\0" });
        await expectRefused(operation, () => use(operation, "in a daemon", SSH_REPOSITORY), {
          transport: "ssh",
          host: SSH_HOST,
        });
        const [, , networkOpts] = calls()[3] as SpawnCall;
        const [, , listingOpts] = calls()[4] as SpawnCall;
        expect("SSH_AUTH_SOCK" in (networkOpts.env as object)).toBe(true);
        expect("SSH_AUTH_SOCK" in (listingOpts.env as object)).toBe(false);
      },
    );

    function linkedWorkTree(): { linked: string; common: string } {
      const common = join(root, "main", ".git");
      mkdirSync(join(common, "objects"), { recursive: true });
      mkdirSync(join(common, "refs"));
      writeFileSync(join(common, "HEAD"), "ref: refs/heads/main\n");
      const linked = join(common, "worktrees", "t");
      mkdirSync(linked, { recursive: true });
      writeFileSync(join(linked, "HEAD"), "ref: refs/heads/t\n");
      writeFileSync(join(linked, "commondir"), "../..\n");
      rmSync(gitDir(), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      writeFileSync(gitDir(), `gitdir: ${linked}\n`);
      return { linked, common };
    }

    const LEGACY_PLACES = ["git directory", "common directory of a linked work tree"] as const;
    const LEGACY_CASES = LOCAL_OPERATIONS.flatMap((operation) =>
      (["remotes", "branches"] as const).flatMap((kind) =>
        LEGACY_PLACES.map((place) => [operation, kind, place] as const),
      ),
    );

    function legacyRepository(place: (typeof LEGACY_PLACES)[number]): {
      probe: string;
      dir: string;
    } {
      if (place === "git directory") return { probe: probeAnswer(), dir: gitDir() };
      const { linked, common } = linkedWorkTree();
      return { probe: probeAnswer({ gitDir: linked, commonDir: common }), dir: common };
    }

    // win32 has no file name with a colon: `remotes/git@h.invalid:remote.git` names a stream there.
    it.skipIf(WIN32 || SSH === null).each(LEGACY_CASES)(
      "in a daemon a legacy remote file named like the address refuses a pull and a fetch: %s, %s/<address> in the %s; served outside a daemon (skipped on win32 and where the native ssh client does not resolve)",
      async (operation, kind, place) => {
        const { probe, dir } = legacyRepository(place);
        mkdirSync(join(dir, kind), { recursive: true });
        writeFileSync(join(dir, kind, LEGACY_REPOSITORY), `URL: ${join(root, "elsewhere")}\n`);
        script({}, probe);
        await expectRefused(operation, () => use(operation, "in a daemon", LEGACY_REPOSITORY), {
          transport: "ssh",
          host: SSH_HOST,
        });

        spawnMock.mockClear();
        log.mockClear();
        const result = await use(operation, "outside a daemon", LEGACY_REPOSITORY);
        expect(result.exit_code).toBe(0);
        expectServed(operation);
      },
    );

    // win32 has no file name with a colon, and there git reads a backslash as a separator.
    it
      .skipIf(WIN32 || SSH === null)
      .each(
        LOCAL_OPERATIONS.flatMap((operation) =>
          (["remotes", "branches"] as const).map((kind) => [operation, kind] as const),
        ),
      )(
      `off win32 a backslash is no separator: %s of ${BACKSLASH_REPOSITORY}, %s/<address> in the git directory, refused in a daemon and served outside one (skipped on win32 and where the native ssh client does not resolve)`,
      async (operation, kind) => {
        mkdirSync(join(gitDir(), kind), { recursive: true });
        writeFileSync(
          join(gitDir(), kind, BACKSLASH_REPOSITORY),
          `URL: ${join(root, "elsewhere")}\n`,
        );
        script();
        await expectRefused(operation, () => use(operation, "in a daemon", BACKSLASH_REPOSITORY), {
          transport: "ssh",
          host: SSH_HOST,
        });

        spawnMock.mockClear();
        log.mockClear();
        const result = await use(operation, "outside a daemon", BACKSLASH_REPOSITORY);
        expect(result.exit_code).toBe(0);
        expectServed(operation);
      },
    );

    function legacyAsked(): string[] {
      return lstatMock.mock.calls
        .map(([path]) => String(path))
        .filter((path) => /[\\/](remotes|branches)([\\/]|$)/.test(path));
    }

    async function expectNothingAsked(operation: LocalOperation, repository: string) {
      script();
      const result = await use(operation, "in a daemon", repository);
      expect(result.exit_code).toBe(0);
      expectServed(operation);
      expect(legacyAsked()).toEqual([]);
    }

    it.each(LOCAL_OPERATIONS)(
      `an address with a separator asks nothing: in a daemon %s of ${HTTPS_REPOSITORY} looks for no legacy remote file`,
      async (operation) => {
        await expectNothingAsked(operation, HTTPS_REPOSITORY);
      },
    );

    it.skipIf(SSH === null).each(LOCAL_OPERATIONS)(
      `an address with a separator asks nothing: in a daemon %s of ${SSH_REPOSITORY} looks for no legacy remote file (skipped where the native ssh client does not resolve)`,
      async (operation) => {
        await expectNothingAsked(operation, SSH_REPOSITORY);
      },
    );

    // Only on win32 does git read a backslash as a directory separator.
    it.runIf(WIN32 && SSH !== null).each(LOCAL_OPERATIONS)(
      `an address with a separator asks nothing: in a daemon %s of ${BACKSLASH_REPOSITORY} looks for no legacy remote file on win32 (skipped off win32 and where the native ssh client does not resolve)`,
      async (operation) => {
        await expectNothingAsked(operation, BACKSLASH_REPOSITORY);
      },
    );

    it
      .skipIf(SSH === null)
      .each(
        LOCAL_OPERATIONS.flatMap((operation) =>
          (["remotes", "branches"] as const).map((kind) => [operation, kind] as const),
        ),
      )(
      "a legacy remote file that cannot be read refuses in a daemon: %s, %s/<address> answering EACCES (skipped where the native ssh client does not resolve)",
      async (operation, kind) => {
        unreadable.set(join(gitDir(), kind, LEGACY_REPOSITORY), "EACCES");
        script();
        await expectRefused(operation, () => use(operation, "in a daemon", LEGACY_REPOSITORY), {
          transport: "ssh",
          host: SSH_HOST,
        });
        expect(legacyAsked()).toContain(join(gitDir(), kind, LEGACY_REPOSITORY));
      },
    );

    it.skipIf(SSH === null).each(LOCAL_OPERATIONS)(
      "a legacy remote file below no directory is no find: %s, remotes/<address> answering ENOTDIR and branches/<address> ENOENT, served in a daemon (skipped where the native ssh client does not resolve)",
      async (operation) => {
        unreadable.set(join(gitDir(), "remotes", LEGACY_REPOSITORY), "ENOTDIR");
        script();
        const result = await use(operation, "in a daemon", LEGACY_REPOSITORY);
        expect(result.exit_code).toBe(0);
        expectServed(operation);
        expect(legacyAsked()).toEqual([
          join(gitDir(), "remotes", LEGACY_REPOSITORY),
          join(gitDir(), "branches", LEGACY_REPOSITORY),
        ]);
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "the repository's own configuration, on real git against a smart-HTTP listener on 127.0.0.1 (skipped where no supported git resolves)",
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

    const url = (name: string) => `http://127.0.0.1:${String(server.port)}/${name}`;
    const markers = () => join(root, "m");

    /** A shell line that creates an empty marker file named `name` under the row's root. */
    function markerProgram(name: string): string {
      return `: > '${printed(join(markers(), name))}'`;
    }

    function servedPolicy(): InjectionPolicy {
      return { ...policy(), url_allowlist: [`http://127.0.0.1:${String(server.port)}/*`] };
    }

    function serve(
      operation: LocalOperation,
      repository: string,
      workingDirectory: string,
      model: Model,
      envAllowlist: string[] = [],
    ) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository, working_directory: workingDirectory },
        SERVED_SECRET,
        { ...servedPolicy(), env_allowlist: envAllowlist },
        undefined,
        "secret-1",
        undefined,
        floorOf(model),
      );
    }

    /** A commit in `dir` that writes `n` to `top.txt`; its id. */
    function commit(dir: string, n: string): string {
      writeFileSync(join(dir, "top.txt"), `${n}\n`);
      git(dir, "add", "top.txt");
      git(dir, "commit", "-q", "-m", `c${n}`);
      return git(dir, "rev-parse", "HEAD").trim();
    }

    /** A bare repository the listener serves, its `main` the first commit of `seed`. */
    function remote(format: "sha1" | "sha256" = "sha1"): {
      name: string;
      bare: string;
      seed: string;
    } {
      remotes += 1;
      const name = `repo-${String(remotes)}.git`;
      const seed = join(root, `seed-${String(remotes)}`);
      git(root, "init", "-q", "-b", "main", `--object-format=${format}`, seed);
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

    /** A work tree cloned from the remote, its origin the listener's address; the remote then moves on. */
    function workTree(): { wt: string; name: string; bare: string; next: string } {
      const { name, bare, seed } = remote();
      const wt = join(root, "wt");
      git(root, "clone", "-q", bare, wt);
      git(wt, "config", "remote.origin.url", url(name));
      const next = advance(seed, bare, "2");
      return { wt, name, bare, next };
    }

    /** Another local repository whose only branch, `planted`, the listener's remote does not have. */
    function elsewhere(): string {
      const dir = join(root, "elsewhere");
      git(root, "init", "-q", "-b", "planted", dir);
      commit(dir, "planted");
      return dir;
    }

    function refListing(wt: string): string {
      return git(wt, "for-each-ref", "--format=%(objectname) %(refname)");
    }

    beforeAll(async () => {
      serverRoot = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-own-config-srv-")));
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

    interface Plant {
      wt: string;
      address: string;
    }

    const PLANTED: ReadonlyArray<readonly [string, (plant: Plant) => void]> = [
      [
        "hook.x.command",
        ({ wt }) => {
          git(wt, "config", "hook.x.command", markerProgram("hook"));
          git(wt, "config", "hook.x.event", "reference-transaction");
        },
      ],
      [
        "filter.f.smudge",
        ({ wt }) => git(wt, "config", "filter.f.smudge", markerProgram("filter")),
      ],
      ["merge.m.driver", ({ wt }) => git(wt, "config", "merge.m.driver", markerProgram("merge"))],
      [
        "url.<another repository>.insteadOf",
        ({ wt, address }) => git(wt, "config", `url.${printed(elsewhere())}.insteadOf`, address),
      ],
      [
        "remote.<address>.url",
        ({ wt, address }) => git(wt, "config", `remote.${address}.url`, printed(elsewhere())),
      ],
      [
        "extensions.partialClone",
        ({ wt }) => git(wt, "config", "extensions.partialClone", "origin"),
      ],
      [
        "fetch.bundleURI",
        ({ wt }) => git(wt, "config", "fetch.bundleURI", printed(join(root, "a.bundle"))),
      ],
      ["http.proactiveAuth", ({ wt }) => git(wt, "config", "http.proactiveAuth", "basic")],
      ["core.sshCommand", ({ wt }) => git(wt, "config", "core.sshCommand", markerProgram("ssh"))],
      ["sequence.editor", ({ wt }) => git(wt, "config", "sequence.editor", markerProgram("seq"))],
      [
        "gc.recentObjectsHook",
        ({ wt }) => git(wt, "config", "gc.recentObjectsHook", markerProgram("gc")),
      ],
      ["gpg.program", ({ wt }) => git(wt, "config", "gpg.program", markerProgram("gpg"))],
      [
        "gpg.ssh.defaultKeyCommand",
        ({ wt }) => git(wt, "config", "gpg.ssh.defaultKeyCommand", markerProgram("gpgssh")),
      ],
      ["protocol.ext.allow", ({ wt }) => git(wt, "config", "protocol.ext.allow", "always")],
      [
        "core.askPass through include.path",
        ({ wt }) => {
          const included = join(root, "included.gitconfig");
          git(root, "config", "--file", included, "core.askPass", markerProgram("askpass"));
          git(wt, "config", "include.path", printed(included));
        },
      ],
    ];

    it.each(
      PLANTED.flatMap(([key, plant]) =>
        LOCAL_OPERATIONS.map((operation) => [operation, key, plant] as const),
      ),
    )(
      "in a daemon a repository with each listed key is refused, nothing run, nothing written: %s, %s",
      async (operation, _key, plant) => {
        const { wt, name } = workTree();
        plant({ wt, address: url(name) });
        const refs = refListing(wt);
        const head = readFileSync(join(wt, ".git", "HEAD"), "utf8");
        const err = await expectVaultError(
          () => serve(operation, url(name), wt, "in a daemon"),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(readdirSync(markers())).toEqual([]);
        expect(err.message).toBe(OWN_CONFIGURATION);
        expect(refListing(wt)).toBe(refs);
        expect(readFileSync(join(wt, ".git", "HEAD"), "utf8")).toBe(head);
      },
      120_000,
    );

    it.each(LOCAL_OPERATIONS)(
      "outside a daemon the same repository is served, but for the hook command: %s",
      async (operation) => {
        const { wt, name, next } = workTree();
        git(wt, "config", "core.sshCommand", markerProgram("ssh"));
        const result = await serve(operation, url(name), wt, "outside a daemon");
        expect(result.exit_code, result.stderr).toBe(0);
        expect(
          git(wt, "rev-parse", operation === "pull" ? "HEAD" : "refs/remotes/origin/main").trim(),
        ).toBe(next);

        git(wt, "config", "--unset", "core.sshCommand");
        git(wt, "config", "hook.x.command", markerProgram("hook"));
        git(wt, "config", "hook.x.event", "reference-transaction");
        const refs = refListing(wt);
        const err = await expectVaultError(
          () => serve(operation, url(name), wt, "outside a daemon"),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(readdirSync(markers())).toEqual([]);
        expect(err.message).toBe(OWN_CONFIGURATION);
        expect(refListing(wt)).toBe(refs);
      },
      120_000,
    );

    /** A local repository that descends from the listener's remote, one commit ahead of it. */
    function ahead(bare: string): string {
      const dir = join(root, "ahead");
      git(root, "clone", "-q", bare, dir);
      commit(dir, "planted");
      return dir;
    }

    it.each(MODELS)(
      "a remote group named like the address, its two members naming another local repository, refuses a pull, and HEAD and the refs stay: %s",
      async (model) => {
        const { wt, name, bare } = workTree();
        const planted = printed(ahead(bare));
        git(wt, "config", "remote.r1.url", planted);
        git(wt, "config", "remote.r2.url", planted);
        git(wt, "config", "remote.r2.fetch", "+refs/heads/*:refs/remotes/r2/*");
        git(wt, "config", `remotes.${url(name)}`, "r1 r2");
        const head = git(wt, "rev-parse", "HEAD").trim();
        const refs = refListing(wt);
        let refusal: unknown;
        try {
          await serve("pull", url(name), wt, model);
        } catch (err) {
          refusal = err;
        }
        expect(git(wt, "rev-parse", "HEAD").trim()).toBe(head);
        expect(refListing(wt)).toBe(refs);
        expect(refusal).toBeInstanceOf(VaultError);
        expect((refusal as VaultError).code).toBe(ErrorCode.INVALID_GIT_CONFIG);
        expect((refusal as VaultError).message).toBe(OWN_CONFIGURATION);
      },
      120_000,
    );

    it.each(LOCAL_OPERATIONS)(
      "the configuration that stands before the local step is the one that is read: %s in a daemon, core.sshCommand written while the network fetch runs",
      async (operation) => {
        const { wt, name } = workTree();
        const refs = refListing(wt);
        spawnMock.mockImplementation((cmd, args, opts) => {
          if (isNetwork(args) && gitSubcommand(args) === "fetch") {
            git(wt, "config", "core.sshCommand", markerProgram("ssh"));
          }
          return realSpawnCaptured(cmd, args, opts);
        });
        const err = await expectVaultError(
          () => serve(operation, url(name), wt, "in a daemon"),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(OWN_CONFIGURATION);
        expect(refListing(wt)).toBe(refs);
      },
      120_000,
    );

    const OWN_CLONES: ReadonlyArray<readonly [string, string[], "sha1" | "sha256"]> = [
      ["a plain clone", [], "sha1"],
      ["--depth=1", ["--depth=1"], "sha1"],
      ["--single-branch --no-tags", ["--single-branch", "--no-tags"], "sha1"],
      ["--sparse", ["--sparse"], "sha1"],
      ["a sha256 remote", [], "sha256"],
    ];

    it.each(OWN_CLONES)(
      "the vault's own clones are served in a daemon: %s, then a fetch and a pull",
      async (_clone, args, format) => {
        const { name, bare, seed } = remote(format);
        const dest = join(root, "cloned");
        const cloned = await new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
          { type: "git", operation: "clone", repository: url(name), working_directory: dest, args },
          SERVED_SECRET,
          servedPolicy(),
          undefined,
          "secret-1",
          undefined,
          floorOf("in a daemon"),
        );
        expect(cloned.exit_code, cloned.stderr).toBe(0);
        const next = advance(seed, bare, "2");
        const fetched = await serve("fetch", url(name), dest, "in a daemon");
        expect(fetched.exit_code, fetched.stderr).toBe(0);
        expect(git(dest, "rev-parse", "refs/remotes/origin/main").trim()).toBe(next);
        const pulled = await serve("pull", url(name), dest, "in a daemon");
        expect(pulled.exit_code, pulled.stderr).toBe(0);
        expect(git(dest, "rev-parse", "HEAD").trim()).toBe(next);
      },
      120_000,
    );

    const OTHER_SPELLINGS: ReadonlyArray<readonly [string, (address: string) => string]> = [
      ["with a trailing slash", (address) => `${address}/`],
      ["with its scheme in upper case", (address) => address.replace(/^http:/, "HTTP:")],
    ];

    it.each(OTHER_SPELLINGS)(
      "a remote named like the address by another spelling is not the address: in a daemon a fetch is served from the relay, the remote planted %s",
      async (_spelling, spell) => {
        const { wt, name, next } = workTree();
        const planted = spell(url(name));
        git(wt, "config", `remote.${planted}.url`, printed(elsewhere()));
        git(wt, "config", `remote.${planted}.fetch`, "+refs/heads/*:refs/remotes/origin/*");
        const result = await serve("fetch", url(name), wt, "in a daemon");
        expect(result.exit_code, result.stderr).toBe(0);
        expect(git(wt, "rev-parse", "refs/remotes/origin/main").trim()).toBe(next);
        expect(git(wt, "for-each-ref", "refs/remotes/origin/planted")).toBe("");
      },
      120_000,
    );

    /** `[url "<root>/e\xFF"] insteadOf = <address>` appended to the tree's `config` as bytes; the base's bytes. */
    function plantNonUtf8Rewrite(wt: string, address: string): Buffer {
      const base = Buffer.concat([Buffer.from(printed(join(root, "e"))), Buffer.from([0xff])]);
      appendFileSync(
        join(wt, ".git", "config"),
        Buffer.concat([Buffer.from('[url "'), base, Buffer.from(`"]\n\tinsteadOf = ${address}\n`)]),
      );
      return base;
    }

    async function expectRefusedInAUtf8Locale(wt: string, name: string): Promise<void> {
      const refs = refListing(wt);
      const err = await withProcessEnv({ LC_ALL: "C.UTF-8" }, () =>
        expectVaultError(
          () => serve("fetch", url(name), wt, "in a daemon", ["LC_ALL"]),
          ErrorCode.INVALID_GIT_CONFIG,
        ),
      );
      expect(err.message).toBe(OWN_CONFIGURATION);
      expect(refListing(wt)).toBe(refs);
    }

    it("the listing is not blinded by a UTF-8 locale: in a daemon, LC_ALL allowlisted and C.UTF-8 in the process, a url.<base>.insteadOf whose base holds the byte 0xFF in the configuration refuses a fetch", async () => {
      const { wt, name } = workTree();
      plantNonUtf8Rewrite(wt, url(name));
      await expectRefusedInAUtf8Locale(wt, name);
    }, 120_000);

    // A file name that is no UTF-8 exists only where the file system takes one: win32 stores names in UTF-16, APFS refuses one (EILSEQ).
    it.skipIf(WIN32 || !NON_UTF8_NAMES)(
      "the listing is not blinded by a UTF-8 locale: the repository a link named by that base leads to is not fetched (skipped on win32 and where the temporary directory's file system refuses a name that is no UTF-8)",
      async () => {
        const { wt, name } = workTree();
        symlinkSync(elsewhere(), plantNonUtf8Rewrite(wt, url(name)));
        await expectRefusedInAUtf8Locale(wt, name);
        expect(git(wt, "for-each-ref", "refs/remotes/origin/planted")).toBe("");
      },
      120_000,
    );

    // win32 has no file name with a colon: `remotes/git@h.invalid:remote.git` names a stream there.
    it.skipIf(WIN32 || SSH === null)(
      "in a daemon remotes/<address> naming another local repository refuses a fetch, and that repository's branch is not in the tree; outside a daemon it arrives (skipped on win32 and where the native ssh client does not resolve)",
      async () => {
        const { wt, bare } = workTree();
        git(wt, "config", "remote.origin.url", LEGACY_REPOSITORY);
        mkdirSync(join(wt, ".git", "remotes"), { recursive: true });
        writeFileSync(join(wt, ".git", "remotes", LEGACY_REPOSITORY), `URL: ${elsewhere()}\n`);
        spawnMock.mockImplementation((cmd, args, opts) =>
          realSpawnCaptured(
            cmd,
            isNetwork(args) ? args.map((a) => (a === LEGACY_REPOSITORY ? bare : a)) : args,
            opts,
          ),
        );
        const key = new Uint8Array(readFileSync(join(FIXTURES, "ssh", "ed25519_openssh")));
        const fetch = (model: Model) =>
          new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
            {
              type: "git",
              operation: "fetch",
              repository: LEGACY_REPOSITORY,
              working_directory: wt,
            },
            key,
            policy(),
            KNOWN_HOSTS,
            "secret-1",
            undefined,
            floorOf(model),
          );
        const err = await expectVaultError(
          () => fetch("in a daemon"),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(OWN_CONFIGURATION);
        expect(git(wt, "for-each-ref", "refs/remotes/origin/planted")).toBe("");

        const result = await fetch("outside a daemon");
        expect(result.exit_code, result.stderr).toBe(0);
        expect(git(wt, "for-each-ref", "--format=%(refname)", "refs/remotes/origin/planted")).toBe(
          "refs/remotes/origin/planted\n",
        );
      },
      120_000,
    );
  },
);
