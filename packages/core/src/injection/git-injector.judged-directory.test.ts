import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

const { spawnCaptured: realSpawnCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");

const GIT = resolveSupportedGit();
const WIN32 = process.platform === "win32";

const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-judged-directory";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const UNRESOLVED = "Git operation failed: could not resolve the working tree's repository";
const HEAD_REF = "ref: refs/heads/main\n";

const TREE_OPERATIONS = ["pull", "push", "fetch"] as const;
type TreeOperation = (typeof TREE_OPERATIONS)[number];

const spawnMock = vi.mocked(spawnCaptured);

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

function unresolvedRow(operation: TreeOperation) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: {
      context: "git",
      operation,
      transport: "https",
      error: "GIT_OPERATION_FAILED",
      network_isolation: false,
      fs_isolation: false,
    },
    success: false,
  };
}

describe.skipIf(GIT === null)(
  "every git step runs in the directory the vault judged, on real git against a smart-HTTP listener on 127.0.0.1 (skipped where no supported git resolves)",
  { timeout: 120_000 },
  () => {
    let serverRoot: string;
    let srv: string;
    let server: Listener;
    let gitEnv: NodeJS.ProcessEnv;
    let remotes = 0;
    let root: string;
    let vaultDir: string;
    let markers: string;
    let log: Mock;

    function git(cwd: string, ...args: string[]): string {
      return execFileSync(GIT as string, args, {
        cwd,
        env: gitEnv,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    }

    const url = (name: string) => `http://127.0.0.1:${String(server.port)}/${name}`;
    const oid = (dir: string, rev: string) => git(dir, "rev-parse", rev).trim();

    function policy(): InjectionPolicy {
      return {
        url_allowlist: [`http://127.0.0.1:${String(server.port)}/*`],
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

    function serve(operation: TreeOperation, name: string, workingDirectory: string) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: url(name), working_directory: workingDirectory },
        SERVED_SECRET,
        policy(),
        undefined,
        "secret-1",
        undefined,
        { vaultFiles: [join(vaultDir, "vault.db"), join(vaultDir, "session.json")] },
      );
    }

    /** A commit in `dir` that writes `n` to `top.txt` and `sub/s.txt`; its id. */
    function commit(dir: string, n: string): string {
      mkdirSync(join(dir, "sub"), { recursive: true });
      writeFileSync(join(dir, "top.txt"), `${n}\n`);
      writeFileSync(join(dir, "sub", "s.txt"), `${n}\n`);
      git(dir, "add", "top.txt", "sub/s.txt");
      git(dir, "commit", "-q", "-m", `c${n}`);
      return oid(dir, "HEAD");
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

    /** A `config` whose programs, were git to run one, write a marker file. */
    function plantedConfig(core: string): string {
      const marker = (name: string) => `: > '${printed(join(markers, name))}'`;
      return `[core]\n${core}\talternateRefsCommand = ${marker("alternate-refs")}\n\tfsmonitor = ${marker("fsmonitor")}\n`;
    }

    /** `HEAD`, `objects` with `alternate` as its alternate, `refs`, and a `config` with the marker programs in `dir`. */
    function plant(dir: string, core: string, alternate: string): void {
      mkdirSync(join(dir, "objects", "info"), { recursive: true });
      writeFileSync(join(dir, "objects", "info", "alternates"), `${printed(alternate)}\n`);
      mkdirSync(join(dir, "refs"), { recursive: true });
      writeFileSync(join(dir, "HEAD"), HEAD_REF);
      writeFileSync(join(dir, "config"), plantedConfig(core));
    }

    beforeAll(async () => {
      serverRoot = realpathSync.native(
        mkdtempSync(join(tmpdir(), "harpoc-git-judged-directory-srv-")),
      );
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
      // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
      root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-judged-directory-")));
      vaultDir = join(root, "vault");
      mkdirSync(vaultDir);
      writeFileSync(join(vaultDir, "vault.db"), "");
      writeFileSync(join(vaultDir, "session.json"), "");
      markers = join(root, "markers");
      mkdirSync(markers);
      log = vi.fn();
      spawnMock.mockReset();
      spawnMock.mockImplementation(realSpawnCaptured);
    });

    afterEach(() => {
      spawnMock.mockReset();
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    afterAll(async () => {
      try {
        if (server !== undefined) await server.close();
      } finally {
        if (serverRoot !== undefined)
          rmSync(serverRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    });

    function plantOnTheNetworkStep(subcommand: "fetch" | "push", wt: string): void {
      spawnMock.mockImplementation((cmd, args, opts) => {
        if (gitSubcommand(args) === subcommand && isNetwork(args)) {
          for (const dir of [join(wt, "sub"), wt]) {
            plant(dir, "\tbare = true\n", join(wt, ".git", "objects"));
          }
        }
        return realSpawnCaptured(cmd, args, opts);
      });
    }

    it.each(["pull", "fetch"] as const)(
      "a directory that takes a repository's shape after the judgement is not asked: a %s named <wt>/sub, the bare shape planted in <wt>/sub and <wt> while the network fetch runs",
      async (operation) => {
        const { name, bare, seed } = remote();
        const wt = join(root, "wt");
        git(root, "clone", "-q", bare, wt);
        git(wt, "config", "remote.origin.url", url(name));
        const head = advance(seed, bare, "2");
        plantOnTheNetworkStep("fetch", wt);
        const result = await serve(operation, name, join(wt, "sub"));
        expect(readdirSync(markers)).toEqual([]);
        expect(result.exit_code, result.stderr).toBe(0);
        expect(existsSync(join(wt, "sub", "objects", "info", "alternates"))).toBe(true);
        expect(oid(wt, operation === "pull" ? "HEAD" : "refs/remotes/origin/main")).toBe(head);
      },
    );

    it("a directory that takes a repository's shape after the judgement is not asked: a push named <wt>/sub, the bare shape planted in <wt>/sub and <wt> while the network push runs", async () => {
      const { name, bare } = remote();
      const wt = join(root, "wt");
      git(root, "clone", "-q", bare, wt);
      const pushed = commit(wt, "2");
      plantOnTheNetworkStep("push", wt);
      const result = await serve("push", name, join(wt, "sub"));
      expect(readdirSync(markers)).toEqual([]);
      expect(result.exit_code, result.stderr).toBe(0);
      expect(existsSync(join(wt, "sub", "objects", "info", "alternates"))).toBe(true);
      expect(oid(bare, "refs/heads/main")).toBe(pushed);
    });

    /** A shape the gate keeps: the directory to name, and the top of its work tree. */
    type Kept = (bare: string, name: string) => { named: string; top: string };

    const KEPT: ReadonlyArray<readonly [string, Kept]> = [
      [
        "a clone's top",
        (bare) => {
          const wt = join(root, "wt");
          git(root, "clone", "-q", bare, wt);
          return { named: wt, top: wt };
        },
      ],
      [
        "a subdirectory",
        (bare) => {
          const wt = join(root, "wt");
          git(root, "clone", "-q", bare, wt);
          return { named: join(wt, "sub"), top: wt };
        },
      ],
      [
        "a linked work tree",
        (bare) => {
          const wt = join(root, "wt");
          git(root, "clone", "-q", bare, wt);
          git(wt, "checkout", "-q", "--detach");
          const linked = join(root, "linked");
          git(wt, "worktree", "add", "-q", linked, "main");
          return { named: linked, top: linked };
        },
      ],
      [
        "a linked work tree of a bare repository",
        (bare) => {
          const local = join(root, "local.git");
          git(root, "clone", "-q", "--bare", bare, local);
          const linked = join(root, "linked");
          git(local, "worktree", "add", "-q", linked, "main");
          return { named: linked, top: linked };
        },
      ],
      [
        "a submodule",
        (bare) => {
          const superproject = join(root, "super");
          git(root, "init", "-q", "-b", "main", superproject);
          writeFileSync(join(superproject, "readme.txt"), "super\n");
          git(superproject, "add", "readme.txt");
          git(superproject, "commit", "-q", "-m", "super");
          git(
            superproject,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            bare,
            "sm",
          );
          git(superproject, "commit", "-q", "-m", "sm");
          const sm = join(superproject, "sm");
          return { named: sm, top: sm };
        },
      ],
      [
        "a separate git directory",
        (bare) => {
          const wt = join(root, "wt");
          git(root, "clone", "-q", `--separate-git-dir=${join(root, "gd")}`, bare, wt);
          return { named: wt, top: wt };
        },
      ],
      [
        "a .git that is a link (a junction on win32)",
        (bare) => {
          const wt = join(root, "wt");
          git(root, "clone", "-q", bare, wt);
          renameSync(join(wt, ".git"), join(root, "gd"));
          symlinkSync(join(root, "gd"), join(wt, ".git"), WIN32 ? "junction" : "dir");
          return { named: wt, top: wt };
        },
      ],
    ];

    it.each(
      KEPT.flatMap(([label, make]) =>
        TREE_OPERATIONS.map((operation) => [operation, label, make] as const),
      ),
    )("the shapes the gate keeps: a %s in %s", async (operation, _label, make) => {
      const { name, bare, seed } = remote();
      const { named, top } = make(bare, name);
      git(top, "config", "remote.origin.url", url(name));
      if (operation === "push") {
        const pushed = commit(top, "2");
        const result = await serve(operation, name, named);
        expect(result.exit_code, result.stderr).toBe(0);
        expect(oid(bare, "refs/heads/main")).toBe(pushed);
        return;
      }
      const head = advance(seed, bare, "2");
      const result = await serve(operation, name, named);
      expect(result.exit_code, result.stderr).toBe(0);
      if (operation === "pull") {
        expect(oid(top, "HEAD")).toBe(head);
        expect(readFileSync(join(top, "sub", "s.txt"), "utf8")).toBe("2\n");
      } else {
        expect(oid(top, "refs/remotes/origin/main")).toBe(head);
      }
    });

    it("a pull that deletes the named subdirectory removes it, whatever the platform", async () => {
      const { name, bare, seed } = remote();
      const wt = join(root, "wt");
      git(root, "clone", "-q", bare, wt);
      git(seed, "rm", "-q", "-r", "sub");
      git(seed, "commit", "-q", "-m", "no sub");
      git(seed, "push", "-q", bare, "HEAD:refs/heads/main");
      const result = await serve("pull", name, join(wt, "sub"));
      expect(result.exit_code, result.stderr).toBe(0);
      expect(oid(wt, "HEAD")).toBe(oid(bare, "refs/heads/main"));
      expect(existsSync(join(wt, "sub"))).toBe(false);
    });

    const DIFFERENCES: ReadonlyArray<readonly [TreeOperation, string, (wt: string) => void]> = [
      ...TREE_OPERATIONS.flatMap((operation) => [
        [
          operation,
          "a .git whose HEAD git does not take, the top holding HEAD, objects and refs",
          (wt: string) => {
            writeFileSync(join(wt, ".git", "HEAD"), "garbage\n");
            plant(wt, "", join(wt, ".git", "objects"));
          },
        ] as const,
        [
          operation,
          "a repository whose config says core.bare = true",
          (wt: string) => {
            git(wt, "config", "core.bare", "true");
          },
        ] as const,
      ]),
      [
        "pull",
        "a repository whose core.worktree names another directory",
        (wt: string) => {
          mkdirSync(join(root, "elsewhere"));
          git(wt, "config", "core.worktree", join(root, "elsewhere"));
        },
      ],
    ];

    it.each(DIFFERENCES)(
      "a difference between the vault's reading and git's ends at the probe: a %s in %s",
      async (operation, _label, differ) => {
        const { name, bare } = remote();
        const wt = join(root, "wt");
        git(root, "clone", "-q", bare, wt);
        git(wt, "config", "remote.origin.url", url(name));
        commit(wt, "2");
        differ(wt);
        const requests = server.requests.length;
        const err = await expectVaultError(
          () => serve(operation, name, wt),
          ErrorCode.GIT_OPERATION_FAILED,
        );
        expect(err.message).toBe(UNRESOLVED);
        expect(log.mock.calls).toEqual([[unresolvedRow(operation)]]);
        expect(server.requests.length).toBe(requests);
        expect(readdirSync(markers)).toEqual([]);
      },
    );

    // Only the Win32 path layer drops a trailing dot from a name; Node reads the name as made.
    it.runIf(WIN32).each(TREE_OPERATIONS)(
      "a difference between the vault's reading and git's ends at the probe: a %s in a linked work tree whose commondir names <wt>\\.git. beside <wt>\\.git",
      async (operation) => {
        const { name, bare } = remote();
        const wt = join(root, "wt");
        git(root, "clone", "-q", bare, wt);
        git(wt, "checkout", "-q", "--detach");
        const linked = join(root, "linked");
        git(wt, "worktree", "add", "-q", linked, "main");
        git(linked, "config", "remote.origin.url", url(name));
        const commondir = join(wt, ".git", "worktrees", "linked", "commondir");
        rmSync(commondir);
        writeFileSync(commondir, `${join(wt, ".git")}.\n`);
        mkdirSync(`${join(wt, ".git")}.`);
        const requests = server.requests.length;
        const err = await expectVaultError(
          () => serve(operation, name, linked),
          ErrorCode.GIT_OPERATION_FAILED,
        );
        expect(err.message).toBe(UNRESOLVED);
        expect(log.mock.calls).toEqual([[unresolvedRow(operation)]]);
        expect(server.requests.length).toBe(requests);
      },
    );

    it.each(["push", "fetch"] as const)(
      "a %s in a repository whose core.worktree names another directory is served",
      async (operation) => {
        const { name, bare, seed } = remote();
        const wt = join(root, "wt");
        git(root, "clone", "-q", bare, wt);
        git(wt, "config", "remote.origin.url", url(name));
        const pushed = commit(wt, "2");
        mkdirSync(join(root, "elsewhere"));
        git(wt, "config", "core.worktree", join(root, "elsewhere"));
        if (operation === "push") {
          const result = await serve(operation, name, wt);
          expect(result.exit_code, result.stderr).toBe(0);
          expect(oid(bare, "refs/heads/main")).toBe(pushed);
          return;
        }
        const head = advance(seed, bare, "2");
        const result = await serve(operation, name, wt);
        expect(result.exit_code, result.stderr).toBe(0);
        expect(oid(wt, "refs/remotes/origin/main")).toBe(head);
      },
    );

    it.each(TREE_OPERATIONS)(
      "a work tree under a directory with a non-ASCII name, and one named in another letter case: %s",
      async (operation) => {
        const { name, bare, seed } = remote();
        const parent = join(root, "tr\u00e9e \u00fc");
        mkdirSync(parent);
        const wt = join(parent, "wt");
        git(root, "clone", "-q", bare, wt);
        git(wt, "config", "remote.origin.url", url(name));
        const upper = wt.toUpperCase();
        const spellings = [wt, ...(upper !== wt && existsSync(upper) ? [upper] : [])];
        for (const [i, spelled] of spellings.entries()) {
          const n = String(i + 2);
          if (operation === "push") {
            const pushed = commit(wt, n);
            const result = await serve(operation, name, spelled);
            expect(result.exit_code, result.stderr).toBe(0);
            expect(oid(bare, "refs/heads/main")).toBe(pushed);
            continue;
          }
          const head = advance(seed, bare, n);
          const result = await serve(operation, name, spelled);
          expect(result.exit_code, result.stderr).toBe(0);
          expect(oid(wt, operation === "pull" ? "HEAD" : "refs/remotes/origin/main")).toBe(head);
        }
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
