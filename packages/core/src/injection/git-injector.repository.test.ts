import { execFileSync } from "node:child_process";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

const SERVER_USER = "vaultuser";
const SERVER_TOKEN = "S3CRET-TOKEN-repository";
const SERVED_SECRET = new Uint8Array(Buffer.from(`${SERVER_USER}:${SERVER_TOKEN}`));
const NOT_SERVED = "working_directory is not in a repository the vault serves";
const HEAD_REF = "ref: refs/heads/main\n";

const TREE_OPERATIONS = ["pull", "push", "fetch"] as const;
type TreeOperation = (typeof TREE_OPERATIONS)[number];

const spawnMock = vi.mocked(spawnCaptured);

/** A path as git prints it, with forward slashes. */
function printed(path: string): string {
  return path.replace(/\\/g, "/");
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

function refusedRow(operation: TreeOperation) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: {
      context: "git",
      operation,
      transport: "https",
      error: "INVALID_GIT_CONFIG",
      network_isolation: false,
      fs_isolation: false,
    },
    success: false,
  };
}

describe.skipIf(GIT === null)(
  "the repository the vault serves, on real git against a smart-HTTP listener on 127.0.0.1 (skipped where no supported git resolves)",
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

    /** A bare repository the listener serves, its `main` one commit of `files`. */
    function remote(files: Record<string, string>): { name: string; bare: string } {
      remotes += 1;
      const name = `repo-${String(remotes)}.git`;
      const seed = join(root, "seed");
      mkdirSync(seed);
      git(seed, "init", "-q", "-b", "main");
      for (const [path, content] of Object.entries({ "file.txt": "1\n", ...files })) {
        const file = join(seed, ...path.split("/"));
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, content);
      }
      git(seed, "add", "-A");
      git(seed, "commit", "-q", "-m", "c1");
      const bare = join(srv, name);
      git(root, "clone", "-q", "--bare", seed, bare);
      return { name, bare };
    }

    /** A `config` whose programs, were git to run one, write a marker file. */
    function plantedConfig(core = ""): string {
      const marker = (name: string) => `: > '${printed(join(markers, name))}'`;
      return `[core]\n${core}\talternateRefsCommand = ${marker("alternate-refs")}\n\tfsmonitor = ${marker("fsmonitor")}\n`;
    }

    function shape(dir: string, config: string): Record<string, string> {
      return {
        [`${dir}/HEAD`]: HEAD_REF,
        [`${dir}/objects/.keep`]: "",
        [`${dir}/refs/.keep`]: "",
        [`${dir}/config`]: config,
      };
    }

    async function expectRefused(
      operation: TreeOperation,
      name: string,
      workingDirectory: string,
    ): Promise<void> {
      const requests = server.requests.length;
      const err = await expectVaultError(
        () => serve(operation, name, workingDirectory),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe(NOT_SERVED);
      expect(log.mock.calls).toEqual([[refusedRow(operation)]]);
      expect(spawnMock).not.toHaveBeenCalled();
      expect(server.requests.length).toBe(requests);
      expect(readdirSync(markers)).toEqual([]);
    }

    beforeAll(async () => {
      serverRoot = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-repository-srv-")));
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
      root = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-repository-")));
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

    const PLANTED: ReadonlyArray<readonly [string, string]> = [
      ["a bare one (core.bare = true)", "p-bare"],
      ["one with core.worktree = ..", "p-worktree"],
      ["one that holds HEAD and commondir alone", "p-commondir"],
      ["one nested in another, the inner named", "p-outer/p-inner"],
      ["a subdirectory of a planted one", "p-bare/sub"],
    ];

    it.each(
      TREE_OPERATIONS.flatMap((operation) =>
        PLANTED.map(([label, named]) => [operation, label, named] as const),
      ),
    )(
      "a planted shape is not served, no git process runs: a %s in %s, a tracked directory of a clone",
      async (operation, _label, named) => {
        const { name, bare } = remote({
          ...shape("p-bare", plantedConfig("\tbare = true\n")),
          "p-bare/sub/s.txt": "1\n",
          ...shape("p-worktree", plantedConfig("\tbare = false\n\tworktree = ..\n")),
          "p-commondir/HEAD": HEAD_REF,
          "p-commondir/commondir": "../.git\n",
          "p-commondir/config": plantedConfig(),
          ...shape("p-outer", plantedConfig("\tbare = true\n")),
          ...shape("p-outer/p-inner", plantedConfig("\tbare = true\n")),
        });
        const wt = join(root, "wt");
        git(root, "clone", "-q", bare, wt);
        await expectRefused(operation, name, join(wt, ...named.split("/")));
      },
    );

    it.each(TREE_OPERATIONS)(
      "a work tree named .git, however it was made: a %s in <B>, whose .git git cloned, is refused and no git process runs",
      async (operation) => {
        const { name, bare } = remote({
          HEAD: HEAD_REF,
          "objects/.keep": "",
          "refs/.keep": "",
          config: plantedConfig(),
        });
        const b = join(root, "B");
        git(root, "clone", "-q", bare, join(b, ".git"));
        await expectRefused(operation, name, b);
      },
    );

    const NO_REPOSITORY: ReadonlyArray<readonly [string, () => string]> = [
      [
        "an empty directory",
        () => {
          const dir = join(root, "empty");
          mkdirSync(dir);
          return dir;
        },
      ],
      [
        "a directory of files",
        () => {
          const dir = join(root, "files");
          mkdirSync(join(dir, "sub"), { recursive: true });
          writeFileSync(join(dir, "a.txt"), "a\n");
          writeFileSync(join(dir, "sub", "b.txt"), "b\n");
          return dir;
        },
      ],
    ];

    it.each(
      TREE_OPERATIONS.flatMap((operation) =>
        NO_REPOSITORY.map(([label, make]) => [operation, label, make] as const),
      ),
    )(
      "a directory that is no repository is the vault's refusal: a %s in %s",
      async (operation, _label, make) => {
        const { name } = remote({});
        expect(repositoriesUpFrom(root), NO_REPOSITORY_ABOVE).toEqual([]);
        await expectRefused(operation, name, make());
      },
    );

    it.each(TREE_OPERATIONS)(
      "a repository without a work tree: a %s in a clone --bare is refused, nothing fetched or pushed",
      async (operation) => {
        const { name, bare } = remote({});
        const local = join(root, "local.git");
        git(root, "clone", "-q", "--bare", bare, local);
        git(local, "config", "remote.origin.url", url(name));
        await expectRefused(operation, name, local);
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
