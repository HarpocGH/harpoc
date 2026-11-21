import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
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
import { delimiter, join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs } from "./allowlist.js";
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

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SSH_HOST = "allowed.invalid";
const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;
const KNOWN_HOSTS: ConnectionConfig = {
  ssh: { known_hosts: [`${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
};
const PINNED_CA: ConnectionConfig = { git: { ca_pem: "unused-ca-pem" } };
const SCRIPTED_SECRET = new Uint8Array(Buffer.from("git-user:work-tree-token-value"));
const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-work-tree";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const UNRESOLVED = "Git operation failed: could not resolve the working tree's repository";
const PROTECTED = "git working directory is inside a directory the vault protects";
const HOLDS_PROTECTED = "git work tree holds a path the vault protects";

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

function failedRow(
  operation: TreeOperation,
  over: Record<string, unknown> = { transport: "https" },
) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: {
      context: "git",
      operation,
      ...over,
      error: "LOCAL_PATH_NOT_ALLOWED",
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

    function use(operation: TreeOperation, floor: Floor = floorAt(vaultDir)) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: HTTPS_REPOSITORY, working_directory: tree() },
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

    function probeAnswer(
      paths: {
        objectsDir?: string;
        shallowFile?: string;
        gitDir?: string;
        commonDir?: string;
      } = {},
    ): string {
      return answer(
        paths.objectsDir ?? join(gitDir(), "objects"),
        paths.shallowFile ?? join(gitDir(), "shallow"),
        "sha1",
        paths.gitDir ?? gitDir(),
        paths.commonDir ?? gitDir(),
      );
    }

    /** spawnCaptured answers by argv: the probe, a pull's top level, the push's HEAD, the fetch's remote; every other step succeeds. */
    function script(answers: { probe?: string; topLevel?: string } = {}): void {
      const probe = answers.probe ?? probeAnswer();
      const topLevel = answers.topLevel ?? answer(tree());
      spawnMock.mockImplementation((_cmd, args) => {
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
      "the probe's argv: %s asks for its git directory and its common directory, and a pull alone for its top level next",
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
        expect(asked.map((call) => calls().indexOf(call))).toEqual(topLevelProbes.map(() => 1));
      },
    );

    const MISCOUNTED: ReadonlyArray<
      readonly [TreeOperation, string, () => { probe?: string; topLevel?: string }]
    > = [
      ...TREE_OPERATIONS.flatMap((operation) => [
        [
          operation,
          "a probe of four lines",
          () => ({
            probe: answer(join(gitDir(), "objects"), join(gitDir(), "shallow"), "sha1", gitDir()),
          }),
        ] as const,
        [
          operation,
          "a probe of six lines, a line feed in a path making one",
          () => ({ probe: probeAnswer({ commonDir: `${gitDir()}\nsplit` }) }),
        ] as const,
      ]),
      ["pull", "a top level of no line", () => ({ topLevel: "" })],
      ["pull", "a top level of two lines", () => ({ topLevel: answer(tree(), tree()) })],
    ];

    it.each(MISCOUNTED)(
      "five lines are taken, four or six refused: %s refuses %s, and goes on with the lines asked for",
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
      ["pull", "top level", 2],
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
        expect(calls()).toHaveLength(2);

        for (const operation of ["push", "fetch"] as const) {
          spawnMock.mockClear();
          const result = await use(operation, floor);
          expect(result.exit_code).toBe(0);
          expect(networkSteps()).toEqual([operation]);
        }
      },
    );

    it("the pull is bound: its local step names the judged top level as its work tree", async () => {
      script();
      const result = await use("pull");
      expect(result.exit_code).toBe(0);
      const [, network] = calls().find(([, a]) => isNetwork(a)) as SpawnCall;
      const relay = (network.find((a) => a.startsWith("--git-dir=")) as string).slice(
        "--git-dir=".length,
      );
      const [, args, opts] = calls().at(-1) as SpawnCall;
      expect(args).toEqual([
        ...FORCED,
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=always",
        "-c",
        `url.${printed(relay)}.insteadOf=${HTTPS_REPOSITORY}`,
        `--work-tree=${tree()}`,
        "pull",
        "--",
        HTTPS_REPOSITORY,
      ]);
      expect(opts.cwd).toBe(tree());
    });

    it.each(TREE_OPERATIONS)(
      "without a floor nothing is judged and the pull is still bound: %s",
      async (operation) => {
        const unresolved = nowhere();
        script({
          probe: probeAnswer({ gitDir: unresolved, commonDir: unresolved }),
          topLevel: answer(root),
        });
        const result = await useWithoutFloor(operation);
        expect(result.exit_code).toBe(0);
        expect(networkSteps()).toEqual([operation === "push" ? "push" : "fetch"]);
        const [, last] = calls().at(-1) as SpawnCall;
        expect(last.filter((a) => a.startsWith("--work-tree="))).toEqual(
          operation === "pull" ? [`--work-tree=${root}`] : [],
        );
      },
    );

    it("without a floor a top level that does not resolve ends the pull with the probe's message", async () => {
      script({ topLevel: answer(nowhere()) });
      const err = await expectVaultError(
        () => useWithoutFloor("pull"),
        ErrorCode.GIT_OPERATION_FAILED,
      );
      expect(err.message).toBe(UNRESOLVED);
      expect(calls()).toHaveLength(2);
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
      expect(calls()).toHaveLength(2);
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

    it("a push and a fetch in a bare repository work as before", async () => {
      const { name, bare, seed } = remote();
      const local = join(root, "local.git");
      git(root, "clone", "-q", "--bare", bare, local);
      const pushed = commit(seed, "2");
      git(seed, "push", "-q", local, "HEAD:refs/heads/main");
      const push = await serve("push", name, local);
      expect(push.exit_code, push.stderr).toBe(0);
      expect(git(bare, "rev-parse", "refs/heads/main").trim()).toBe(pushed);

      const fetched = advance(seed, bare, "3");
      git(local, "config", "remote.origin.url", url(name));
      const fetch = await serve("fetch", name, local);
      expect(fetch.exit_code, fetch.stderr).toBe(0);
      expect(git(local, "rev-parse", "refs/remotes/origin/main").trim()).toBe(fetched);
    });

    it("a pull in a bare repository ends at the second probe, nothing fetched", async () => {
      const { name, bare } = remote();
      const local = join(root, "local.git");
      git(root, "clone", "-q", "--bare", bare, local);
      const requests = server.requests.length;
      const result = await serve("pull", name, local);
      expect(result.exit_code).toBe(128);
      expect(server.requests.length).toBe(requests);
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
    });
  },
);
