import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs } from "./allowlist.js";
import { localStepWords } from "./__fixtures__/git-local-steps.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import type { readGitVersion } from "./git-injector-version.js";
import { GitInjector } from "./git-injector.js";
import type { DaemonPaths } from "./local-path.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";

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

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SSH_HOST = "allowed.invalid";
const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;
const KNOWN_HOSTS: ConnectionConfig = {
  ssh: { known_hosts: [`${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
};
const PINNED_CA: ConnectionConfig = { git: { ca_pem: "unused-ca-pem" } };
const SCRIPTED_USER = "git-user";
const SCRIPTED_TOKEN = "work-tree-token-value";
const SCRIPTED_SECRET = new Uint8Array(Buffer.from(`${SCRIPTED_USER}:${SCRIPTED_TOKEN}`));
const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-work-tree";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const UNRESOLVED = "Git operation failed: could not resolve the working tree's repository";
const PROTECTED = "git working directory is inside a directory the vault protects";
const HOLDS_PROTECTED = "git work tree holds a path the vault protects";
const NOT_SERVED = "working_directory is not in a repository the vault serves";

const TREE_OPERATIONS = ["pull", "push", "fetch"] as const;
type TreeOperation = (typeof TREE_OPERATIONS)[number];
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
const PROBE = [
  "rev-parse",
  "--path-format=absolute",
  "--git-path",
  "objects",
  "--git-path",
  "shallow",
  "--show-object-format",
  "--absolute-git-dir",
  "--git-common-dir",
  "--is-bare-repository",
];
const TOP_LEVEL_PROBE = ["rev-parse", "--path-format=absolute", "--show-toplevel"];

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
  root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-work-tree-")));
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

function calls(): SpawnCall[] {
  return spawnMock.mock.calls as SpawnCall[];
}

function networkSteps(): Array<string | undefined> {
  return calls()
    .filter(([, args]) => isNetwork(args))
    .map(([, args]) => gitSubcommand(args));
}

const NO_REPOSITORY_ABOVE =
  "a directory from the fixture's root up holds a .git entry or a git directory's shape: a row that names a directory outside any repository needs a host without one";

function entryThere(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code !== "ENOENT" && code !== "ENOTDIR";
  }
}

/** The directories from `dir` up to the root that hold a `.git` entry or a git directory's shape. */
function repositoriesUpFrom(dir: string): string[] {
  const found: string[] = [];
  for (let current = dir; ; current = dirname(current)) {
    const there = (name: string) => entryThere(join(current, name));
    if (
      there(".git") ||
      (there("HEAD") && (there("commondir") || (there("objects") && there("refs"))))
    ) {
      found.push(current);
    }
    if (dirname(current) === current) return found;
  }
}

function failedRow(
  operation: TreeOperation,
  over: Record<string, unknown> = { transport: "https" },
  error = "LOCAL_PATH_NOT_ALLOWED",
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

describe.skipIf(GIT === null)(
  "the repository git reports in the working tree, scripted (skipped where no supported git resolves)",
  () => {
    const tree = () => join(root, "tree");
    const gitDir = () => join(root, "tree", ".git");

    function use(
      operation: TreeOperation,
      floor: Floor = floorAt(vaultDir),
      workingDirectory: string = tree(),
    ) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        {
          type: "git",
          operation,
          repository: HTTPS_REPOSITORY,
          working_directory: workingDirectory,
        },
        SCRIPTED_SECRET,
        policy(),
        undefined,
        "secret-1",
        undefined,
        floor,
      );
    }

    function useWithoutFloor(operation: TreeOperation) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: HTTPS_REPOSITORY, working_directory: tree() },
        SCRIPTED_SECRET,
        policy(),
        undefined,
        "secret-1",
      );
    }

    function probeOf(dir: string): string {
      return probeAnswer({
        objectsDir: join(dir, "objects"),
        shallowFile: join(dir, "shallow"),
        gitDir: dir,
        commonDir: dir,
      });
    }

    function probeAnswer(
      paths: {
        objectsDir?: string;
        shallowFile?: string;
        gitDir?: string;
        commonDir?: string;
        bare?: string;
      } = {},
    ): string {
      return answer(
        paths.objectsDir ?? join(gitDir(), "objects"),
        paths.shallowFile ?? join(gitDir(), "shallow"),
        "sha1",
        paths.gitDir ?? gitDir(),
        paths.commonDir ?? gitDir(),
        paths.bare ?? "false",
      );
    }

    function gitDirectoryAt(dir: string): string {
      mkdirSync(join(dir, "objects"), { recursive: true });
      mkdirSync(join(dir, "refs"));
      writeFileSync(join(dir, "HEAD"), "ref: refs/heads/main\n");
      return dir;
    }

    /** spawnCaptured answers by argv: the read of the ref storage as absent, the probe, a pull's top level, the push's HEAD, the fetch's remote; every other step succeeds. */
    function script(
      answers: { probe?: string; topLevel?: string } = {},
      failing?: { step: (args: string[]) => boolean; result: SpawnCapturedResult },
    ): void {
      const probe = answers.probe ?? probeAnswer();
      const topLevel = answers.topLevel ?? answer(tree());
      spawnMock.mockImplementation((_cmd, args) => {
        if (failing?.step(args) === true) return Promise.resolve(failing.result);
        if (args.includes("extensions.refStorage")) {
          return Promise.resolve({ ...OK_STEP, exit_code: 1 });
        }
        const sub = gitSubcommand(args);
        let stdout = "";
        if (args.includes("--git-path")) stdout = probe;
        else if (args.includes("--show-toplevel")) stdout = topLevel;
        else if (sub === "symbolic-ref") stdout = "refs/heads/main\n";
        else if (sub === "config") stdout = "remote.origin.url\0";
        return Promise.resolve({ ...OK_STEP, stdout });
      });
    }

    /** A link that leads nowhere: a junction on win32, which needs no privilege. */
    function nowhere(): string {
      const link = join(root, "nowhere");
      symlinkSync(join(root, "gone"), link, WIN32 ? "junction" : "dir");
      return link;
    }

    function underTheVault(): string {
      const dir = join(vaultDir, "repo");
      mkdirSync(dir);
      return dir;
    }

    /** A link into the vault's directory: a junction on win32, which needs no privilege. */
    function intoTheVault(): string {
      const link = join(root, "into-the-vault");
      symlinkSync(underTheVault(), link, WIN32 ? "junction" : "dir");
      return link;
    }

    const TOP_LEVEL_PROBES: ReadonlyArray<readonly [TreeOperation, ReadonlyArray<string[]>]> = [
      ["pull", [TOP_LEVEL_PROBE]],
      ["push", []],
      ["fetch", []],
    ];

    it.each(TOP_LEVEL_PROBES)(
      "the probe's argv: %s asks for its git directory and its common directory, and a pull alone for its top level after the read of the ref storage",
      async (operation, topLevelProbes) => {
        script();
        const result = await use(operation);
        expect(result.exit_code).toBe(0);
        const [, args, opts] = calls()[0] as SpawnCall;
        expect(args).toEqual([...FORCED, ...PROBE]);
        expect(opts.cwd).toBe(tree());
        const asked = calls().filter(([, a]) => a.includes("--show-toplevel"));
        expect(asked.map(([, a, o]) => [a, o.cwd])).toEqual(
          topLevelProbes.map((probe) => [[...FORCED, ...probe], tree()]),
        );
        expect(asked.map((call) => calls().indexOf(call))).toEqual(topLevelProbes.map(() => 2));
      },
    );

    const MISCOUNTED: ReadonlyArray<
      readonly [TreeOperation, string, () => { probe?: string; topLevel?: string }]
    > = [
      ...TREE_OPERATIONS.flatMap((operation) => [
        [
          operation,
          "a probe of five lines, the answer before the bare question",
          () => ({
            probe: answer(
              join(gitDir(), "objects"),
              join(gitDir(), "shallow"),
              "sha1",
              gitDir(),
              gitDir(),
            ),
          }),
        ] as const,
        [
          operation,
          "a probe of seven lines, a line feed in a path making one",
          () => ({ probe: probeAnswer({ commonDir: `${gitDir()}\nsplit` }) }),
        ] as const,
      ]),
      ["pull", "a top level of no line", () => ({ topLevel: "" })],
      ["pull", "a top level of two lines", () => ({ topLevel: answer(tree(), tree()) })],
    ];

    it.each(MISCOUNTED)(
      "six lines are taken, five or seven refused: %s refuses %s, and goes on with the lines asked for",
      async (operation, _label, answers) => {
        script(answers());
        const err = await expectVaultError(() => use(operation), ErrorCode.GIT_OPERATION_FAILED);
        expect(err.message).toBe(UNRESOLVED);
        expect(networkSteps()).toEqual([]);

        spawnMock.mockReset();
        script();
        const result = await use(operation);
        expect(result.exit_code).toBe(0);
        expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);
      },
    );

    const ANSWERS = {
      "git directory": (dir: string) => ({ probe: probeAnswer({ gitDir: dir }) }),
      "common directory": (dir: string) => ({ probe: probeAnswer({ commonDir: dir }) }),
      "top level": (dir: string) => ({ topLevel: answer(dir) }),
    };
    const UNDER_THE_FLOOR_ANSWERS: ReadonlyArray<
      readonly [TreeOperation, keyof typeof ANSWERS, number]
    > = [
      ...TREE_OPERATIONS.flatMap((operation) => [
        [operation, "git directory", 1] as const,
        [operation, "common directory", 1] as const,
      ]),
      ["pull", "top level", 3],
    ];
    const UNDER_THE_FLOOR_SPELLINGS: ReadonlyArray<readonly [string, () => string]> = [
      ["inside the vault's directory", underTheVault],
      ["a link that leads nowhere", nowhere],
    ];
    const UNDER_THE_FLOOR_CASES = UNDER_THE_FLOOR_ANSWERS.flatMap(
      ([operation, which, answeredBy]) =>
        UNDER_THE_FLOOR_SPELLINGS.map(
          ([spelling, spell]) => [operation, which, spelling, answeredBy, spell] as const,
        ),
    );

    it.each(UNDER_THE_FLOOR_CASES)(
      "a git directory, a common directory and a top level under the floor are refused: %s, its %s %s",
      async (operation, which, _spelling, answeredBy, spell) => {
        script(ANSWERS[which](spell()));
        const err = await expectVaultError(() => use(operation), ErrorCode.LOCAL_PATH_NOT_ALLOWED);
        expect(err.message).toBe(PROTECTED);
        expect(log.mock.calls).toEqual([[failedRow(operation)]]);
        expect(calls()).toHaveLength(answeredBy);
      },
    );

    const unresolvedRow = (operation: TreeOperation) =>
      failedRow(operation, { transport: "https" }, "GIT_OPERATION_FAILED");

    async function expectUnresolved(
      operation: TreeOperation,
      run: () => Promise<unknown>,
      answeredBy: number,
    ): Promise<void> {
      const err = await expectVaultError(run, ErrorCode.GIT_OPERATION_FAILED);
      expect(err.message).toBe(UNRESOLVED);
      expect(log.mock.calls).toEqual([[unresolvedRow(operation)]]);
      expect(calls()).toHaveLength(answeredBy);
      expect(networkSteps()).toEqual([]);
    }

    it.each(TREE_OPERATIONS)(
      "every step runs in the top level, whatever directory was named: %s named <tree>/sub/deep",
      async (operation) => {
        const named = join(tree(), "sub", "deep");
        mkdirSync(named, { recursive: true });
        script();
        const result = await use(operation, floorAt(vaultDir), named);
        expect(result.exit_code).toBe(0);
        const inTheTree = calls().filter(([, args]) => !isNetwork(args));
        expect(inTheTree.map(([, , opts]) => opts.cwd)).toEqual(
          Array<string>(operation === "push" ? 4 : 7).fill(tree()),
        );
        const [, last] = calls().at(-1) as SpawnCall;
        expect(last.filter((a) => a.startsWith("--work-tree="))).toEqual(
          operation === "pull" ? [`--work-tree=${tree()}`] : [],
        );
      },
    );

    it.each(
      TREE_OPERATIONS.flatMap((operation) =>
        ["true", "maybe"].map((bare) => [operation, bare] as const),
      ),
    )(
      "a repository that calls itself bare is refused: %s, the sixth line %s",
      async (operation, bare) => {
        script({ probe: probeAnswer({ bare }) });
        await expectUnresolved(operation, () => use(operation), 1);
      },
    );

    function otherRepository(): string {
      const other = join(root, "other");
      gitDirectoryAt(join(other, ".git"));
      return other;
    }

    const ANOTHER_READING: ReadonlyArray<readonly [TreeOperation, keyof typeof ANSWERS, number]> = [
      ...TREE_OPERATIONS.flatMap((operation) => [
        [operation, "git directory", 1] as const,
        [operation, "common directory", 1] as const,
      ]),
      ["pull", "top level", 3],
    ];
    const ANOTHER_READING_CASES = ANOTHER_READING.flatMap(([operation, which, answeredBy]) =>
      (["with a floor", "without a floor"] as const).map(
        (floored) => [operation, which, floored, answeredBy] as const,
      ),
    );

    it.each(ANOTHER_READING_CASES)(
      "git's answer must be the vault's reading: %s, its %s another repository's, %s",
      async (operation, which, floored, answeredBy) => {
        const other = otherRepository();
        script(ANSWERS[which](which === "top level" ? other : join(other, ".git")));
        await expectUnresolved(
          operation,
          () => (floored === "with a floor" ? use(operation) : useWithoutFloor(operation)),
          answeredBy,
        );
      },
    );

    it.each(TREE_OPERATIONS)(
      "a linked work tree's common directory is the vault's reading: %s is served where git answers the directory commondir names, refused where it answers the git directory",
      async (operation) => {
        const common = gitDirectoryAt(join(root, "main", ".git"));
        const linked = join(common, "worktrees", "t");
        mkdirSync(linked, { recursive: true });
        writeFileSync(join(linked, "HEAD"), "ref: refs/heads/t\n");
        writeFileSync(join(linked, "commondir"), "../..\n");
        rmSync(gitDir(), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        writeFileSync(gitDir(), `gitdir: ${linked}\n`);
        const answered = (commonDir: string) =>
          probeAnswer({
            objectsDir: join(common, "objects"),
            shallowFile: join(common, "shallow"),
            gitDir: linked,
            commonDir,
          });

        script({ probe: answered(common) });
        const result = await use(operation);
        expect(result.exit_code).toBe(0);
        expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);

        spawnMock.mockReset();
        log.mockClear();
        script({ probe: answered(linked) });
        await expectUnresolved(operation, () => use(operation), 1);
      },
    );

    const FAILED_STEPS: ReadonlyArray<readonly [string, () => SpawnCapturedResult]> = [
      [
        "exits 128 naming the tree",
        () => ({
          ...OK_STEP,
          exit_code: 128,
          stderr: `fatal: detected dubious ownership in repository at '${printed(tree())}'\n`,
        }),
      ],
      [
        "times out",
        () => ({
          ...OK_STEP,
          exit_code: null,
          timed_out: true,
          signal: "SIGKILL",
          stdout: `${printed(tree())}\n`,
        }),
      ],
      [
        "fails to spawn",
        () => ({ ...OK_STEP, exit_code: null, spawn_failed: true, stderr: `${tree()}\n` }),
      ],
    ];
    const FAILED_PROBES: ReadonlyArray<
      readonly [TreeOperation, string, (args: string[]) => boolean, number]
    > = [
      ...TREE_OPERATIONS.map(
        (operation) =>
          [operation, "first probe", (args: string[]) => args.includes("--git-path"), 1] as const,
      ),
      ["pull", "top-level probe", (args: string[]) => args.includes("--show-toplevel"), 3],
    ];
    const FAILED_PROBE_CASES = FAILED_PROBES.flatMap(([operation, which, step, answeredBy]) =>
      FAILED_STEPS.map(
        ([how, result]) => [operation, which, how, step, result, answeredBy] as const,
      ),
    );

    it.each(FAILED_PROBE_CASES)(
      "a probe that fails is the vault's refusal, with nothing of git's text: %s, its %s %s",
      async (operation, _which, _how, step, result, answeredBy) => {
        script({}, { step, result: result() });
        const err = await expectVaultError(() => use(operation), ErrorCode.GIT_OPERATION_FAILED);
        const spelled = [tree(), printed(tree()), JSON.stringify(tree()).slice(1, -1)];
        const texts = [err.message, JSON.stringify(err), JSON.stringify(log.mock.calls)];
        expect(texts.some((text) => spelled.some((path) => text.includes(path)))).toBe(false);
        expect(err.message).toBe(UNRESOLVED);
        expect(log.mock.calls).toEqual([[unresolvedRow(operation)]]);
        expect(calls()).toHaveLength(answeredBy);
        expect(networkSteps()).toEqual([]);
      },
    );

    const RETURNED_PROBES: ReadonlyArray<
      readonly [TreeOperation, string, (args: string[]) => boolean]
    > = [
      [
        "push",
        "its HEAD question rev-parse --verify HEAD",
        (args) => gitSubcommand(args) === "symbolic-ref" || args.includes("--verify"),
      ],
      ...TREE_OPERATIONS.map(
        (operation) =>
          [
            operation,
            "its ref listing",
            (args: string[]) => gitSubcommand(args) === "for-each-ref",
          ] as const,
      ),
    ];

    it.each(RETURNED_PROBES)(
      "a later probe that fails is still git's result, returned through the redaction: %s, %s",
      async (operation, _which, step) => {
        script(
          {},
          {
            step,
            result: {
              ...OK_STEP,
              exit_code: 128,
              stderr: `fatal: ${SCRIPTED_USER} could not read ${SCRIPTED_TOKEN}\n`,
            },
          },
        );
        const result = await use(operation);
        expectAbsent(result.stderr, SCRIPTED_USER, "the result's stderr");
        expectAbsent(result.stderr, SCRIPTED_TOKEN, "the result's stderr");
        expect(result.exit_code).toBe(128);
        expect(result.stderr.includes("[REDACTED]")).toBe(true);
        expect(log.mock.calls).toEqual([
          [
            {
              eventType: "secret.use",
              secretId: "secret-1",
              detail: {
                context: "git",
                operation,
                transport: "https",
                exit_code: 128,
                network_isolation: false,
                fs_isolation: false,
                sanitized: true,
              },
              success: true,
            },
          ],
        ]);
        expect(calls()).toHaveLength(4);
        expect(networkSteps()).toEqual([]);
      },
    );

    const OBJECTS_AND_SHALLOW = {
      "objects directory": (path: string) => probeAnswer({ objectsDir: path }),
      "shallow file": (path: string) => probeAnswer({ shallowFile: path }),
    };
    const OBJECTS_AND_SHALLOW_SPELLINGS: ReadonlyArray<
      readonly [keyof typeof OBJECTS_AND_SHALLOW, string, () => string]
    > = [
      ["objects directory", "inside the vault's directory", underTheVault],
      ["objects directory", "a link into the vault's directory", intoTheVault],
      ["objects directory", "a link that leads nowhere", nowhere],
      ["shallow file", "a file inside the vault's directory", () => join(vaultDir, "session.json")],
      [
        "shallow file",
        "a missing name inside the vault's directory",
        () => join(vaultDir, "shallow"),
      ],
      ["shallow file", "a link that leads nowhere", nowhere],
    ];
    const OBJECTS_AND_SHALLOW_CASES = TREE_OPERATIONS.flatMap((operation) =>
      OBJECTS_AND_SHALLOW_SPELLINGS.map(
        ([which, spelling, spell]) => [operation, which, spelling, spell] as const,
      ),
    );

    async function expectRefusedAtTheProbe(operation: TreeOperation, probe: string): Promise<void> {
      script({ probe });
      const err = await expectVaultError(() => use(operation), ErrorCode.LOCAL_PATH_NOT_ALLOWED);
      expect(err.message).toBe(PROTECTED);
      expect(log.mock.calls).toEqual([[failedRow(operation)]]);
      expect(calls()).toHaveLength(1);
    }

    it.each(OBJECTS_AND_SHALLOW_CASES)(
      "an objects directory and a shallow file under the floor are refused: %s, its %s %s",
      async (operation, which, _spelling, spell) => {
        await expectRefusedAtTheProbe(operation, OBJECTS_AND_SHALLOW[which](spell()));
      },
    );

    it.skipIf(WIN32).each(TREE_OPERATIONS)(
      "a shallow file that is a link to a file under the floor is refused: %s (skipped on win32, where a file link needs a privilege)",
      async (operation) => {
        const shallow = join(gitDir(), "shallow");
        symlinkSync(join(vaultDir, "session.json"), shallow);
        await expectRefusedAtTheProbe(operation, probeAnswer({ shallowFile: shallow }));
      },
    );

    it.each(TREE_OPERATIONS)(
      "a shallow file outside the floor is taken, one that does not exist yet and one that does: %s",
      async (operation) => {
        const shallow = join(gitDir(), "shallow");
        for (const exists of [false, true]) {
          if (exists) writeFileSync(shallow, "");
          spawnMock.mockReset();
          script({ probe: probeAnswer({ shallowFile: shallow }) });
          const result = await use(operation);
          expect(result.exit_code).toBe(0);
          expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);
        }
      },
    );

    // Git for Windows prints forward slashes, and only win32 has a junction without a privilege.
    it
      .runIf(WIN32)
      .each(
        TREE_OPERATIONS.flatMap((operation) =>
          (["as made", "in lower case"] as const).map((spelling) => [operation, spelling] as const),
        ),
      )(
      "a git directory git spells through a junction, its shallow file missing, is served: %s, spelled %s",
      async (operation, spelling) => {
        const through = join(root, "jt", ".git");
        symlinkSync(tree(), join(root, "jt"), "junction");
        const spell = (line: string) => (spelling === "as made" ? line : line.toLowerCase());
        script({
          probe: answer(
            ...[
              join(through, "objects"),
              join(through, "shallow"),
              "sha1",
              through,
              through,
              "false",
            ].map((line) => spell(printed(line))),
          ),
        });
        const result = await use(operation);
        expect(result.exit_code).toBe(0);
        expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);
      },
    );

    // Git for Windows prints forward slashes, and only win32 has a junction without a privilege.
    it.runIf(WIN32).each(TREE_OPERATIONS)(
      "a junction into the vault's directory with a missing shallow file stays refused: %s",
      async (operation) => {
        await expectRefusedAtTheProbe(
          operation,
          probeAnswer({ shallowFile: join(intoTheVault(), "shallow") }),
        );
      },
    );

    // Only off win32 can a name end in a carriage return.
    it.skipIf(WIN32)(
      "a name that ends in a carriage return is judged as it is: a pull in <root>/tree\\r beside <root>/tree",
      async () => {
        const named = join(root, "tree\r");
        script({ probe: probeOf(gitDirectoryAt(join(named, ".git"))), topLevel: answer(named) });
        const result = await use("pull", floorAt(vaultDir), named);
        expect(result.exit_code).toBe(0);
        const inTheTree = calls().filter(([, args]) => !isNetwork(args));
        expect(inTheTree.map(([, , opts]) => opts.cwd)).toEqual(Array<string>(7).fill(named));
        const [, last] = calls().at(-1) as SpawnCall;
        expect(last.filter((a) => a.startsWith("--work-tree="))).toEqual([`--work-tree=${named}`]);
      },
    );

    // Only off win32 can a name end in a carriage return.
    it.skipIf(WIN32).each(TREE_OPERATIONS)(
      "a git directory whose name ends in a carriage return is judged as it is: %s in a tree whose .git is a link to <root>/gd\\r beside <root>/gd",
      async (operation) => {
        const named = gitDirectoryAt(join(root, "gd\r"));
        gitDirectoryAt(join(root, "gd"));
        rmSync(gitDir(), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        symlinkSync(named, gitDir(), "dir");
        script({ probe: probeOf(named) });
        const result = await use(operation);
        expect(result.exit_code).toBe(0);
        expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);
      },
    );

    it.skipIf(SSH === null)(
      "over SSH a git directory under the floor refuses a pull, the row naming the host, and a pull is bound to its top level (skipped where the native ssh client does not resolve)",
      async () => {
        const key = generateKeyPairSync("rsa", {
          modulusLength: 2048,
          privateKeyEncoding: { type: "pkcs1", format: "pem" },
          publicKeyEncoding: { type: "spki", format: "pem" },
        }).privateKey;
        const pull = () =>
          new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
            {
              type: "git",
              operation: "pull",
              repository: SSH_REPOSITORY,
              working_directory: tree(),
            },
            new Uint8Array(Buffer.from(key)),
            policy(),
            KNOWN_HOSTS,
            "secret-1",
            undefined,
            floorAt(vaultDir),
          );

        script({ probe: probeAnswer({ gitDir: underTheVault() }) });
        const err = await expectVaultError(pull, ErrorCode.LOCAL_PATH_NOT_ALLOWED);
        expect(err.message).toBe(PROTECTED);
        expect(log.mock.calls).toEqual([[failedRow("pull", { transport: "ssh", host: SSH_HOST })]]);
        expect(calls()).toHaveLength(1);

        spawnMock.mockReset();
        script();
        const result = await pull();
        expect(result.exit_code).toBe(0);
        const [, last] = calls().at(-1) as SpawnCall;
        expect(last.filter((a) => a.startsWith("--work-tree="))).toEqual([`--work-tree=${tree()}`]);
      },
    );

    it("with a CA pinned the refusal's row carries ca_pinned", async () => {
      script({ probe: probeAnswer({ gitDir: underTheVault() }) });
      const err = await expectVaultError(
        () =>
          new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
            {
              type: "git",
              operation: "pull",
              repository: HTTPS_REPOSITORY,
              working_directory: tree(),
            },
            SCRIPTED_SECRET,
            policy(),
            PINNED_CA,
            "secret-1",
            undefined,
            floorAt(vaultDir),
          ),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(err.message).toBe(PROTECTED);
      expect(log.mock.calls).toEqual([
        [failedRow("pull", { transport: "https", ca_pinned: true })],
      ]);
      expect(calls()).toHaveLength(1);
    });

    function plain(): string {
      const dir = join(root, "plain");
      mkdirSync(dir);
      expect(repositoriesUpFrom(root), NO_REPOSITORY_ABOVE).toEqual([]);
      return dir;
    }

    it.skipIf(SSH === null)(
      "over SSH a pull in a directory without .git is refused, the row naming the host, nothing spawned (skipped where the native ssh client does not resolve)",
      async () => {
        const key = generateKeyPairSync("rsa", {
          modulusLength: 2048,
          privateKeyEncoding: { type: "pkcs1", format: "pem" },
          publicKeyEncoding: { type: "spki", format: "pem" },
        }).privateKey;
        script();
        const dir = plain();
        const err = await expectVaultError(
          () =>
            new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
              {
                type: "git",
                operation: "pull",
                repository: SSH_REPOSITORY,
                working_directory: dir,
              },
              new Uint8Array(Buffer.from(key)),
              policy(),
              KNOWN_HOSTS,
              "secret-1",
              undefined,
              floorAt(vaultDir),
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(NOT_SERVED);
        expect(log.mock.calls).toEqual([
          [
            {
              eventType: "secret.use",
              secretId: "secret-1",
              detail: {
                context: "git",
                operation: "pull",
                transport: "ssh",
                host: SSH_HOST,
                error: "INVALID_GIT_CONFIG",
                network_isolation: false,
                fs_isolation: false,
              },
              success: false,
            },
          ],
        ]);
        expect(calls()).toHaveLength(0);
      },
    );

    it("with a CA pinned a pull in a directory without .git is refused, the row carrying ca_pinned", async () => {
      script();
      const dir = plain();
      const err = await expectVaultError(
        () =>
          new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
            {
              type: "git",
              operation: "pull",
              repository: HTTPS_REPOSITORY,
              working_directory: dir,
            },
            SCRIPTED_SECRET,
            policy(),
            PINNED_CA,
            "secret-1",
            undefined,
            floorAt(vaultDir),
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe(NOT_SERVED);
      expect(log.mock.calls).toEqual([
        [
          {
            eventType: "secret.use",
            secretId: "secret-1",
            detail: {
              context: "git",
              operation: "pull",
              transport: "https",
              error: "INVALID_GIT_CONFIG",
              network_isolation: false,
              fs_isolation: false,
              ca_pinned: true,
            },
            success: false,
          },
        ],
      ]);
      expect(calls()).toHaveLength(0);
    });

    it.each([
      ["the vault's directory", () => ({ topLevel: root, daemon: undefined })],
      [
        "a daemon's declared file",
        () => {
          const elsewhere = join(root, "elsewhere");
          mkdirSync(elsewhere);
          writeFileSync(join(elsewhere, "token"), "");
          return {
            topLevel: elsewhere,
            daemon: { protectedDirs: [], protectedFiles: [join(elsewhere, "token")] },
          };
        },
      ],
    ] as const)(
      "a protected path inside the top level refuses a pull, not a push or a fetch: a top level that holds %s",
      async (_label, make) => {
        const { topLevel, daemon } = make();
        const floor = floorAt(vaultDir, daemon);
        script({ topLevel: answer(topLevel) });
        const err = await expectVaultError(
          () => use("pull", floor),
          ErrorCode.LOCAL_PATH_NOT_ALLOWED,
        );
        expect(err.message).toBe(HOLDS_PROTECTED);
        expect(log.mock.calls).toEqual([[failedRow("pull")]]);
        expect(calls()).toHaveLength(3);

        for (const operation of ["push", "fetch"] as const) {
          spawnMock.mockClear();
          const result = await use(operation, floor);
          expect(result.exit_code).toBe(0);
          expect(networkSteps()).toEqual([operation]);
        }
      },
    );

    it("the pull is bound: named below the top level, its local step names the judged top level as its work tree", async () => {
      const sub = join(tree(), "sub");
      mkdirSync(sub);
      script();
      const result = await use("pull", floorAt(vaultDir), sub);
      expect(result.exit_code).toBe(0);
      const [, network] = calls().find(([, a]) => isNetwork(a)) as SpawnCall;
      const relay = (network.find((a) => a.startsWith("--git-dir=")) as string).slice(
        "--git-dir=".length,
      );
      const [, args, opts] = calls().at(-1) as SpawnCall;
      expect(args).toEqual([
        ...FORCED,
        ...localStepWords(WIN32 ? "NUL" : "/dev/null"),
        "-c",
        `url.${printed(relay)}.insteadOf=${HTTPS_REPOSITORY}`,
        `--work-tree=${tree()}`,
        "pull",
        "--no-recurse-submodules",
        "--upload-pack=git-upload-pack",
        "--",
        HTTPS_REPOSITORY,
      ]);
      expect(opts.cwd).toBe(tree());
    });

    // A link is a junction on win32, which needs no privilege.
    it.each(TREE_OPERATIONS)(
      "without a floor no answer is judged against one, the equalities hold, and the pull is still bound: %s, its .git a link to a git directory inside the vault's directory",
      async (operation) => {
        const inside = gitDirectoryAt(join(vaultDir, "gd"));
        rmSync(gitDir(), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        symlinkSync(inside, gitDir(), WIN32 ? "junction" : "dir");
        script({ probe: probeOf(inside) });
        const result = await useWithoutFloor(operation);
        expect(result.exit_code).toBe(0);
        expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);
        const [, last] = calls().at(-1) as SpawnCall;
        expect(last.filter((a) => a.startsWith("--work-tree="))).toEqual(
          operation === "pull" ? [`--work-tree=${tree()}`] : [],
        );

        spawnMock.mockReset();
        log.mockClear();
        await expectRefusedAtTheProbe(operation, probeOf(inside));
      },
    );

    it("without a floor a top level that does not resolve ends the pull with the probe's message", async () => {
      script({ topLevel: answer(nowhere()) });
      const err = await expectVaultError(
        () => useWithoutFloor("pull"),
        ErrorCode.GIT_OPERATION_FAILED,
      );
      expect(err.message).toBe(UNRESOLVED);
      expect(calls()).toHaveLength(3);
    });

    async function expectReadAsAnother(name: string, floored: boolean): Promise<void> {
      const named = join(root, name);
      mkdirSync(named);
      script({ topLevel: answer(named) });
      const err = await expectVaultError(
        () => (floored ? use("pull") : useWithoutFloor("pull")),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(err.message).toBe(PROTECTED);
      expect(calls()).toHaveLength(3);
    }

    it.each([
      ["with a floor", true],
      ["without a floor", false],
    ])(
      "a top level git could read as another directory is refused: U+FFFD in its last name, %s",
      async (_label, floored) => {
        await expectReadAsAnother("tr\uFFFDee", floored);
      },
    );

    // Only the Win32 path layer drops a trailing dot from a name; Node makes the directory as spelled.
    it.runIf(WIN32).each([
      ["with a floor", true],
      ["without a floor", false],
    ])(
      "a top level git could read as another directory is refused: a last name that ends in a dot, %s",
      async (_label, floored) => {
        await expectReadAsAnother("tree.", floored);
      },
    );
  },
);

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no supported git resolves',
    );
  }
});

describe.skipIf(GIT === null)(
  "the work tree git reports, on real git against a smart-HTTP listener on 127.0.0.1 (skipped where no supported git resolves)",
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

    function servedPolicy(): InjectionPolicy {
      return { ...policy(), url_allowlist: [`http://127.0.0.1:${String(server.port)}/*`] };
    }

    function serve(
      operation: TreeOperation,
      name: string,
      workingDirectory: string,
      floor: Floor = floorAt(vaultDir),
    ) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: url(name), working_directory: workingDirectory },
        SERVED_SECRET,
        servedPolicy(),
        undefined,
        "secret-1",
        undefined,
        floor,
      );
    }

    /** A commit in `dir` that writes `n` to `top.txt` and `sub/s.txt`; its id. */
    function commit(dir: string, n: string): string {
      mkdirSync(join(dir, "sub"), { recursive: true });
      writeFileSync(join(dir, "top.txt"), `${n}\n`);
      writeFileSync(join(dir, "sub", "s.txt"), `${n}\n`);
      git(dir, "add", "top.txt", "sub/s.txt");
      git(dir, "commit", "-q", "-m", `c${n}`);
      return git(dir, "rev-parse", "HEAD").trim();
    }

    /** A bare repository the listener serves, its `main` the first commit of `seed`. */
    function remote(): { name: string; bare: string; seed: string } {
      remotes += 1;
      const name = `repo-${String(remotes)}.git`;
      const seed = join(root, "seed");
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

    beforeAll(async () => {
      serverRoot = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-work-tree-srv-")));
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

    it("a tree whose config names the vault's directory while the fetch runs: the pull lands in the tree the vault judged", async () => {
      const { name, bare, seed } = remote();
      const wt = join(root, "wt");
      git(root, "clone", "-q", bare, wt);
      const head = advance(seed, bare, "2");
      const entries = readdirSync(vaultDir).sort();
      spawnMock.mockImplementation((cmd, args, opts) => {
        if (gitSubcommand(args) === "fetch" && isNetwork(args)) {
          git(wt, "config", "core.worktree", vaultDir);
        }
        return realSpawnCaptured(cmd, args, opts);
      });
      const result = await serve("pull", name, wt);
      expect(result.exit_code, result.stderr).toBe(0);
      expect(git(wt, "rev-parse", "HEAD").trim()).toBe(head);
      expect(readFileSync(join(wt, "top.txt"), "utf8")).toBe("2\n");
      expect(readdirSync(vaultDir).sort()).toEqual(entries);
    });

    it("a pull from a subdirectory lands where it did: the remote's changes at the top level's paths, nothing new beside them", async () => {
      const { name, bare, seed } = remote();
      const wt = join(root, "wt");
      git(root, "clone", "-q", bare, wt);
      advance(seed, bare, "2");
      const result = await serve("pull", name, join(wt, "sub"));
      expect(result.exit_code, result.stderr).toBe(0);
      expect(readFileSync(join(wt, "top.txt"), "utf8")).toBe("2\n");
      expect(readFileSync(join(wt, "sub", "s.txt"), "utf8")).toBe("2\n");
      expect(readdirSync(join(wt, "sub"))).toEqual(["s.txt"]);
    });

    it("a pull in a work tree that holds the vault's directory is refused, nothing fetched; a push and a fetch there are served", async () => {
      const { name, bare } = remote();
      const wt = join(root, "wt");
      git(root, "clone", "-q", bare, wt);
      const inside = join(wt, "vault");
      mkdirSync(inside);
      writeFileSync(join(inside, "vault.db"), "");
      writeFileSync(join(inside, "session.json"), "");
      const floor = floorAt(inside);
      const requests = server.requests.length;
      const err = await expectVaultError(
        () => serve("pull", name, wt, floor),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(err.message).toBe(HOLDS_PROTECTED);
      expect(server.requests.length).toBe(requests);

      const pushed = commit(wt, "2");
      const push = await serve("push", name, wt, floor);
      expect(push.exit_code, push.stderr).toBe(0);
      expect(git(bare, "rev-parse", "refs/heads/main").trim()).toBe(pushed);

      git(wt, "config", "remote.origin.url", url(name));
      const fetch = await serve("fetch", name, wt, floor);
      expect(fetch.exit_code, fetch.stderr).toBe(0);
      expect(git(wt, "rev-parse", "refs/remotes/origin/main").trim()).toBe(pushed);
      expect(server.requests.length).toBeGreaterThan(requests);
    }, 120_000);
  },
);
