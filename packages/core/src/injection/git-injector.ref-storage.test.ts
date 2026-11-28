import { execFileSync } from "node:child_process";
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { InjectionPolicy, VaultError } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import { refStorageArgs } from "./git-injector-local-steps.js";
import type { readGitVersion } from "./git-injector-version.js";
import { GitInjector } from "./git-injector.js";
import type { DaemonPaths } from "./local-path.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
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

const GIT = resolveSupportedGit();
const REF_STORAGE_GIT = resolveSupportedGit([2, 54]);

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SCRIPTED_SECRET = new Uint8Array(Buffer.from("git-user:ref-storage-token-value"));
const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-ref-storage";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const FOREIGN_REF_STORAGE =
  "working_directory's repository names a ref storage the vault does not serve";
const UNLISTED = "Git operation failed: the repository's configuration could not be listed";
const NO_PATHS: DaemonPaths = { protectedDirs: [], protectedFiles: [] };
const NO_HIT_LISTING = "remote.origin.url\0remote.origin.fetch\0";
const READ = "the ref storage";

const OPERATIONS = ["pull", "push", "fetch"] as const;
type Operation = (typeof OPERATIONS)[number];
const LOCAL_OPERATIONS = ["pull", "fetch"] as const;
const MODELS = ["outside a daemon", "in a daemon"] as const;
type Model = (typeof MODELS)[number];
type Floor = Parameters<GitInjector["executeWithSecret"]>[6];
type SpawnCall = Parameters<typeof spawnCaptured>;

const SERVED: Record<Operation, string[]> = {
  pull: ["rev-parse", READ, "rev-parse", "for-each-ref", "network fetch", "listing", READ, "pull"],
  push: ["rev-parse", READ, "symbolic-ref", "for-each-ref", "network push"],
  fetch: ["rev-parse", READ, "config", "for-each-ref", "network fetch", "listing", READ, "fetch"],
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

const ABSENT: Partial<SpawnCapturedResult> = { exit_code: 1, stdout: "" };
const WITH_A_PATH: Partial<SpawnCapturedResult> = { stdout: "files:///x\0" };

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

function isRefStorageRead(args: string[]): boolean {
  return args.includes("extensions.refStorage");
}

/** A path as git prints it, with forward slashes. */
function printed(path: string): string {
  return path.replace(/\\/g, "/");
}

/** git's answer of one line each, paths as git prints them. */
function answer(...lines: string[]): string {
  return lines.map((line) => `${printed(line)}\n`).join("");
}

function policy(urlAllowlist: string[] = ["https://8.8.8.8/*"]): InjectionPolicy {
  return {
    url_allowlist: urlAllowlist,
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
    local_dirs: [],
    ssh_bootstrap: null,
    render: { entries: [], approvals: [] },
  };
}

const spawnMock = vi.mocked(spawnCaptured);
let root: string;
let vaultDir: string;
let log: Mock;

beforeEach(() => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-ref-storage-")));
  vaultDir = join(root, "vault");
  mkdirSync(vaultDir);
  writeFileSync(join(vaultDir, "vault.db"), "");
  writeFileSync(join(vaultDir, "session.json"), "");
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

function steps(): string[] {
  return calls().map(([, args]) => {
    if (isRefStorageRead(args)) return READ;
    if (isListing(args)) return "listing";
    const sub = gitSubcommand(args) as string;
    return isNetwork(args) ? `network ${sub}` : sub;
  });
}

function failedRow(operation: Operation, error: string) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: {
      context: "git",
      operation,
      transport: "https",
      error,
      network_isolation: false,
      fs_isolation: false,
    },
    success: false,
  };
}

it("ssh-live tier: required legs fail instead of skipping when no git of 2.54 or later resolves", () => {
  if (REF_STORAGE_GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git of 2.54 or later resolves',
    );
  }
});

describe.skipIf(GIT === null)(
  "the repository's ref storage, read right after the first probe, scripted (skipped where no supported git resolves)",
  () => {
    const tree = () => join(root, "tree");
    const gitDir = () => join(root, "tree", ".git");

    beforeEach(() => {
      mkdirSync(join(gitDir(), "objects"), { recursive: true });
      mkdirSync(join(gitDir(), "refs"));
      writeFileSync(join(gitDir(), "HEAD"), "ref: refs/heads/main\n");
    });

    function use(operation: Operation, model: Model) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: HTTPS_REPOSITORY, working_directory: tree() },
        SCRIPTED_SECRET,
        policy(),
        undefined,
        "secret-1",
        undefined,
        floorOf(model),
      );
    }

    /** spawnCaptured answers by argv: the first read of the ref storage `first`, every later one `later`, the probe, a pull's top level, the push's HEAD, the fetch's remote lookup and the listing as a served repository; every other step succeeds. */
    function script(
      first: Partial<SpawnCapturedResult> = ABSENT,
      later: Partial<SpawnCapturedResult> = first,
    ): void {
      const probe = answer(
        join(gitDir(), "objects"),
        join(gitDir(), "shallow"),
        "sha1",
        gitDir(),
        gitDir(),
        "false",
      );
      let reads = 0;
      spawnMock.mockImplementation((_cmd, args) => {
        if (isRefStorageRead(args)) {
          reads += 1;
          return Promise.resolve({ ...OK_STEP, ...(reads === 1 ? first : later) });
        }
        if (isListing(args)) return Promise.resolve({ ...OK_STEP, stdout: NO_HIT_LISTING });
        let stdout = "";
        if (args.includes("--git-path")) stdout = probe;
        else if (args.includes("--show-toplevel")) stdout = answer(tree());
        else if (gitSubcommand(args) === "symbolic-ref") stdout = "refs/heads/main\n";
        else if (args.includes("--fixed-value")) stdout = "remote.origin.url\0";
        return Promise.resolve({ ...OK_STEP, stdout });
      });
    }

    const BY_OPERATION_AND_MODEL = OPERATIONS.flatMap((operation) =>
      MODELS.map((model) => [operation, model] as const),
    );

    const SERVED_ANSWERS: ReadonlyArray<readonly [string, Partial<SpawnCapturedResult>]> = [
      ["exit 1 with nothing printed", ABSENT],
      ["files", { stdout: "files\0" }],
      ["reftable", { stdout: "reftable\0" }],
    ];

    it.each(
      SERVED_ANSWERS.flatMap(([how, read]) =>
        BY_OPERATION_AND_MODEL.map(([operation, model]) => [how, operation, model, read] as const),
      ),
    )(
      "a ref storage the vault serves lets the operation run on: %s, %s %s",
      async (_how, operation, model, read) => {
        script(read);
        const result = await use(operation, model);
        expect(result.exit_code).toBe(0);
        expect(steps()).toEqual(SERVED[operation]);
      },
    );

    it.each(OPERATIONS)(
      "the read's argv and place: %s reads the ref storage in the top, behind the forced configuration alone, on the local environment with LC_ALL=C",
      async (operation) => {
        script();
        const result = await use(operation, "outside a daemon");
        expect(result.exit_code).toBe(0);
        const reads = calls().filter(([, args]) => isRefStorageRead(args));
        expect(reads).toHaveLength(operation === "push" ? 1 : 2);
        const [, , probeOpts] = calls()[0] as SpawnCall;
        for (const [, args, opts] of reads) {
          expect(args).toEqual([...FORCED, ...refStorageArgs()]);
          expect(opts.cwd).toBe(tree());
          expect(opts.env).toEqual({ ...probeOpts.env, LC_ALL: "C" });
        }
      },
    );

    const FOREIGN_VALUES = [
      "files:///x\0",
      "reftable://x\0",
      "files://\0",
      "Files\0",
      "files\n\0",
      "files\0files:///x\0",
      "\0",
    ];

    it.each(
      FOREIGN_VALUES.flatMap((stdout) =>
        BY_OPERATION_AND_MODEL.map(([operation, model]) => [stdout, operation, model] as const),
      ),
    )(
      "a ref storage the vault does not serve refuses with no git process after the read: %j, %s %s",
      async (stdout, operation, model) => {
        script({ stdout });
        const err = await expectVaultError(
          () => use(operation, model),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(FOREIGN_REF_STORAGE);
        expect(log.mock.calls).toEqual([[failedRow(operation, "INVALID_GIT_CONFIG")]]);
        expect(steps()).toEqual(["rev-parse", READ]);
      },
    );

    const SECRET_PATH = "SECRET-PATH";
    const NAMING_A_PATH = `fatal: bad config line 3 in file /srv/${SECRET_PATH}/config\n`;
    const FAILED_READS: ReadonlyArray<readonly [string, Partial<SpawnCapturedResult>]> = [
      ["exit 2 naming a path", { exit_code: 2, stdout: "", stderr: NAMING_A_PATH }],
      ["exit 1 with an output", { exit_code: 1, stdout: "files\0", stderr: NAMING_A_PATH }],
      [
        "timed out",
        {
          exit_code: null,
          timed_out: true,
          signal: "SIGKILL",
          stdout: "files\0",
          stderr: NAMING_A_PATH,
        },
      ],
      [
        "failed to spawn",
        { exit_code: null, spawn_failed: true, stdout: "", stderr: NAMING_A_PATH },
      ],
      [
        "cut by the output cap on exit 0",
        { exit_code: 0, truncated: true, stdout: "files\0", stderr: NAMING_A_PATH },
      ],
    ];

    it.each(
      FAILED_READS.flatMap(([how, read]) =>
        OPERATIONS.map((operation) => [how, operation, read] as const),
      ),
    )(
      "a read that fails refuses and returns nothing of its output: %s, %s",
      async (_how, operation, read) => {
        script(read);
        const err = await expectVaultError(
          () => use(operation, "outside a daemon"),
          ErrorCode.GIT_OPERATION_FAILED,
        );
        expect(err.message.includes(SECRET_PATH)).toBe(false);
        expect(JSON.stringify(err).includes(SECRET_PATH)).toBe(false);
        expect(JSON.stringify(log.mock.calls).includes(SECRET_PATH)).toBe(false);
        expect(err.message).toBe(UNLISTED);
        expect(log.mock.calls).toEqual([[failedRow(operation, "GIT_OPERATION_FAILED")]]);
        expect(steps()).toEqual(["rev-parse", READ]);
      },
    );

    it.each(
      LOCAL_OPERATIONS.flatMap((operation) => MODELS.map((model) => [operation, model] as const)),
    )(
      "a ref storage named while the network fetch runs is read again before the local step: %s %s, the first read absent, the second files:///x",
      async (operation, model) => {
        script(ABSENT, WITH_A_PATH);
        const err = await expectVaultError(
          () => use(operation, model),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(FOREIGN_REF_STORAGE);
        expect(log.mock.calls).toEqual([[failedRow(operation, "INVALID_GIT_CONFIG")]]);
        expect(steps()).toEqual(SERVED[operation].slice(0, -1));
      },
    );

    it.each(
      LOCAL_OPERATIONS.flatMap((operation) =>
        FAILED_READS.filter(([how]) => how === "exit 2 naming a path" || how === "timed out").map(
          ([how, read]) => [operation, how, read] as const,
        ),
      ),
    )(
      "a second read that fails refuses before the local step and returns nothing of its output: %s, the first read absent, the second %s",
      async (operation, _how, read) => {
        script(ABSENT, read);
        const err = await expectVaultError(
          () => use(operation, "outside a daemon"),
          ErrorCode.GIT_OPERATION_FAILED,
        );
        expect(err.message.includes(SECRET_PATH)).toBe(false);
        expect(JSON.stringify(err).includes(SECRET_PATH)).toBe(false);
        expect(JSON.stringify(log.mock.calls).includes(SECRET_PATH)).toBe(false);
        expect(err.message).toBe(UNLISTED);
        expect(log.mock.calls).toEqual([[failedRow(operation, "GIT_OPERATION_FAILED")]]);
        expect(steps()).toEqual(SERVED[operation].slice(0, -1));
      },
    );

    it.each(MODELS)(
      "a push reads the ref storage once: %s, a second read would answer files:///x",
      async (model) => {
        script(ABSENT, WITH_A_PATH);
        const result = await use("push", model);
        expect(result.exit_code).toBe(0);
        expect(steps()).toEqual(SERVED.push);
      },
    );

    it("a clone reads no ref storage: every read would answer files:///x", async () => {
      script(WITH_A_PATH);
      const result = await new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        {
          type: "git",
          operation: "clone",
          repository: HTTPS_REPOSITORY,
          working_directory: join(root, "new"),
        },
        SCRIPTED_SECRET,
        policy(),
        undefined,
        "secret-1",
        undefined,
        floorOf("outside a daemon"),
      );
      expect(result.exit_code).toBe(0);
      expect(steps()).toEqual(["network ls-remote", "network fetch", "clone"]);
    });

    it("an ls-remote reads no ref storage: every read would answer files:///x", async () => {
      script(WITH_A_PATH);
      const result = await new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation: "ls-remote", repository: HTTPS_REPOSITORY },
        SCRIPTED_SECRET,
        policy(),
        undefined,
        "secret-1",
        undefined,
        floorOf("outside a daemon"),
      );
      expect(result.exit_code).toBe(0);
      expect(steps()).toEqual(["network ls-remote"]);
    });
  },
);

describe.skipIf(REF_STORAGE_GIT === null)(
  "a ref storage with a path, on real git against a smart-HTTP listener on 127.0.0.1 (skipped where no git of 2.54 or later resolves)",
  () => {
    let serverRoot: string;
    let server: Listener;
    let gitEnv: NodeJS.ProcessEnv;

    function git(cwd: string, ...args: string[]): string {
      return execFileSync(REF_STORAGE_GIT as string, args, {
        cwd,
        env: gitEnv,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    }

    const address = () => `http://127.0.0.1:${String(server.port)}/repo.git`;

    beforeAll(async () => {
      serverRoot = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-ref-storage-srv-")));
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
      const seed = join(serverRoot, "seed");
      git(serverRoot, "init", "-q", "-b", "main", seed);
      writeFileSync(join(seed, "top.txt"), "1\n");
      git(seed, "add", "top.txt");
      git(seed, "commit", "-q", "-m", "c1");
      const srv = join(serverRoot, "srv");
      mkdirSync(srv);
      git(serverRoot, "clone", "-q", "--bare", seed, join(srv, "repo.git"));
      server = await startGitSmartHttp({
        git: REF_STORAGE_GIT as string,
        projectRoot: srv,
        user: SERVER_USER,
        token: SERVER_TOKEN,
        env: gitEnv,
      });
    });

    beforeEach(() => {
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

    it("a fetch in a repository whose extensions.RefStorage names files://<a directory outside it> is refused, and nothing is written there", async () => {
      const wt = join(root, "wt");
      git(root, "init", "-q", "-b", "main", wt);
      git(wt, "remote", "add", "origin", address());
      git(wt, "config", "core.repositoryFormatVersion", "1");
      const outside = join(root, "outside");
      mkdirSync(outside);
      appendFileSync(
        join(wt, ".git", "config"),
        `[extensions]\n\tRefStorage = files://${printed(outside)}\n`,
      );
      let refusal: VaultError | undefined;
      try {
        refusal = await expectVaultError(
          () =>
            new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
              { type: "git", operation: "fetch", repository: address(), working_directory: wt },
              SERVED_SECRET,
              policy([`http://127.0.0.1:${String(server.port)}/*`]),
              undefined,
              "secret-1",
              undefined,
              floorAt(vaultDir),
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
      } finally {
        expect(readdirSync(outside)).toEqual([]);
      }
      expect((refusal as VaultError).message).toBe(FOREIGN_REF_STORAGE);
    }, 120_000);
  },
);
