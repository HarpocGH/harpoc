import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { GitResult, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { GitInjector } from "./git-injector.js";

const GIT = resolveExecutable("git", controlledPathDirs());
// Skipped where git does not resolve.
const describeGit = describe.skipIf(GIT === null);

const USER = "probe_user";
const TOKEN = "PR0BE-TOKEN-xyz";
const SECRET = new Uint8Array(Buffer.from(`${USER}:${TOKEN}`));

type Scenario = "pull" | "push" | "fetch" | "branch" | "refs";

interface Run {
  result: GitResult | string;
  configKept: boolean;
}

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

describeGit("Git working-tree probes read unredacted — real git over smart HTTP (RG-6)", () => {
  const injector = new GitInjector(null);
  let root: string;
  let srv: string;
  let bare: string;
  let seed: string;
  let home: string;
  let wd: string;
  let vaultTemp: string;
  let server: Listener;
  let gitEnv: NodeJS.ProcessEnv;
  const saved: Record<string, string | undefined> = {};

  function git(cwd: string, ...args: string[]): string {
    try {
      return execFileSync(GIT as string, args, {
        cwd,
        env: gitEnv,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 20_000,
      });
    } catch {
      throw new Error("a git step of the fixture failed");
    }
  }

  function quiet<T>(run: () => T): T {
    try {
      return run();
    } catch {
      throw new Error("a file step of the fixture failed");
    }
  }

  const oid = (dir: string, rev: string) => git(dir, "rev-parse", rev).trim();
  const exitOf = (outcome: GitResult | string) =>
    typeof outcome === "string" ? outcome : outcome.exit_code;
  const url = () => `http://127.0.0.1:${String(server.port)}/repo.git`;

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
    };
  }

  function commit(dir: string, text: string): void {
    quiet(() => writeFileSync(join(dir, "f.txt"), `${text}\n`));
    git(dir, "add", "f.txt");
    git(dir, "commit", "-q", "-m", text);
  }

  function moveRemote(): void {
    commit(seed, "remote");
    git(seed, "push", "-q", bare, "main");
  }

  async function use(operation: "pull" | "push" | "fetch", args?: string[]): Promise<Run> {
    const config = quiet(() => readFileSync(join(wd, ".git", "config")));
    const result = await injector
      .executeWithSecret(
        {
          type: "git",
          operation,
          repository: url(),
          working_directory: wd,
          ...(args ? { args } : {}),
        },
        SECRET,
        policy(),
        undefined,
      )
      .then(
        (r) => r,
        (e: unknown) => (e instanceof VaultError ? e.code : "threw"),
      );
    return {
      result,
      configKept: quiet(() => readFileSync(join(wd, ".git", "config"))).equals(config),
    };
  }

  const scenarios: Record<Scenario, () => Promise<Run[]>> = {
    pull: async () => {
      quiet(() => writeFileSync(join(seed, `${USER}.txt`), "named\n"));
      git(seed, "add", `${USER}.txt`);
      moveRemote();
      git(bare, "branch", `${USER}-feature`, "main");
      return [await use("pull", ["--ff-only"])];
    },
    push: async () => {
      commit(wd, "local");
      return [await use("push")];
    },
    fetch: async () => {
      moveRemote();
      git(bare, "branch", `${USER}-feature`, "main");
      return [await use("fetch")];
    },
    branch: async () => {
      git(wd, "checkout", "-q", "-b", `${USER}-topic`);
      commit(wd, "topic");
      return [await use("push")];
    },
    refs: async () => {
      git(wd, "branch", `${USER}-local`, "HEAD~1");
      git(wd, "tag", `${USER}-tag`, "HEAD~1");
      moveRemote();
      return [await use("fetch"), await use("pull", ["--ff-only"])];
    },
  };

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-probes-"));
    const emptyConfig = join(root, "empty.gitconfig");
    writeFileSync(emptyConfig, "");
    gitEnv = {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: emptyConfig,
      GIT_DEFAULT_REF_FORMAT: "files",
      GIT_TERMINAL_PROMPT: "0",
      GIT_AUTHOR_NAME: "harpoc-test",
      GIT_AUTHOR_EMAIL: "test@example.com",
      GIT_COMMITTER_NAME: "harpoc-test",
      GIT_COMMITTER_EMAIL: "test@example.com",
    };
    srv = join(root, "srv");
    mkdirSync(srv);
    bare = join(srv, "repo.git");
  });

  beforeEach(async () => {
    for (const key of ["TMPDIR", "TMP", "TEMP"]) saved[key] = process.env[key];
    const run = mkdtempSync(join(root, "run-"));
    seed = join(run, "seed");
    git(run, "init", "-q", "-b", "main", seed);
    for (const n of ["1", "2", "3"]) commit(seed, n);
    rmSync(bare, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    git(srv, "clone", "-q", "--bare", seed, "repo.git");
    server = await startGitSmartHttp({
      git: GIT as string,
      projectRoot: srv,
      user: USER,
      token: TOKEN,
      env: gitEnv,
    });
    home = join(run, `${USER}-home`);
    quiet(() => mkdirSync(home));
    wd = join(home, "wd");
    git(run, "clone", "-q", bare, wd);
    git(wd, "remote", "set-url", "origin", url());
    git(wd, "checkout", "-q", "-b", "work");
    commit(wd, "unpushed");
    git(wd, "checkout", "-q", "main");
    vaultTemp = mkdtempSync(join(root, "vault-tmp-"));
    process.env.TMPDIR = vaultTemp;
    process.env.TMP = vaultTemp;
    process.env.TEMP = vaultTemp;
  });

  afterEach(async () => {
    for (const key of ["TMPDIR", "TMP", "TEMP"]) {
      const value = saved[key];
      if (value === undefined) Reflect.deleteProperty(process.env, key);
      else process.env[key] = value;
    }
    await server.close();
    expect(readdirSync(vaultTemp)).toEqual([]);
  });

  afterAll(() => {
    if (root !== undefined)
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("a pull in a tree whose path contains the credential's user name succeeds", async () => {
    const [pulled] = (await scenarios.pull()) as [Run];
    expect(exitOf(pulled.result)).toBe(0);
    expect(oid(wd, "main")).toBe(oid(bare, "main"));
  });

  it("a push from a tree whose path contains the credential's user name succeeds", async () => {
    const [pushed] = (await scenarios.push()) as [Run];
    expect(exitOf(pushed.result)).toBe(0);
    expect(oid(bare, "main")).toBe(oid(wd, "HEAD"));
  });

  it("a fetch in a tree whose path contains the credential's user name succeeds", async () => {
    const [fetched] = (await scenarios.fetch()) as [Run];
    expect(exitOf(fetched.result)).toBe(0);
    expect(oid(wd, "refs/remotes/origin/main")).toBe(oid(bare, "main"));
  });

  it("a push from a checked-out branch whose name carries the credential's user name lands that branch on the remote", async () => {
    const [pushed] = (await scenarios.branch()) as [Run];
    expect(exitOf(pushed.result)).toBe(0);
    expect(oid(bare, `refs/heads/${USER}-topic`)).toBe(oid(wd, "HEAD"));
  });

  it("a fetch and a pull in a tree that also holds a branch and a tag named with the credential's user name succeed", async () => {
    const before = oid(wd, "HEAD~1");
    const [fetched, pulled] = (await scenarios.refs()) as [Run, Run];
    expect(exitOf(fetched.result)).toBe(0);
    expect(exitOf(pulled.result)).toBe(0);
    expect(oid(wd, "refs/remotes/origin/main")).toBe(oid(bare, "main"));
    expect(oid(wd, "main")).toBe(oid(bare, "main"));
    expect(oid(wd, `refs/heads/${USER}-local`)).toBe(before);
    expect(oid(wd, `refs/tags/${USER}-tag`)).toBe(before);
  });

  it.each([
    ["a pull", "pull"],
    ["a push", "push"],
    ["a fetch", "fetch"],
    ["a push of a branch named with the user name", "branch"],
    ["a fetch and a pull beside a branch and a tag named with the user name", "refs"],
  ] as const)(
    "the result of %s carries neither the credential's user name nor its token, and .git/config is byte-identical",
    async (_title, scenario) => {
      const runs = await scenarios[scenario]();
      for (const { result, configKept } of runs) {
        expect(result).toBeTypeOf("object");
        expect(JSON.stringify(result).includes(USER)).toBe(false);
        expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
        expect(configKept).toBe(true);
      }
    },
  );

  it("a push from a detached HEAD in a tree whose path contains the credential's user name: the plain push is refused by git as in any tree, --all lands the unpushed branch, and neither result carries the user name or the token", async () => {
    git(wd, "checkout", "-q", "--detach");
    commit(wd, "detached");
    const remoteRefs = () => git(bare, "for-each-ref", "--format=%(refname) %(objectname)");
    const before = remoteRefs();
    const plain = await use("push");
    expect(exitOf(plain.result)).toBe(128);
    expect(remoteRefs() === before).toBe(true);
    const all = await use("push", ["--all"]);
    expect(exitOf(all.result)).toBe(0);
    expect(oid(bare, "refs/heads/work")).toBe(oid(wd, "refs/heads/work"));
    for (const { result, configKept } of [plain, all]) {
      expect(JSON.stringify(result).includes(USER)).toBe(false);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      expect(configKept).toBe(true);
    }
  });

  it("a clone of a repository whose default branch is named with the credential's user name lands on that branch (it is the only branch at HEAD's commit)", async () => {
    const named = join(srv, "named.git");
    rmSync(named, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    git(srv, "clone", "-q", "--bare", seed, "named.git");
    git(named, "branch", `${USER}-main`, "main");
    git(named, "update-ref", "refs/heads/main", "main~1");
    git(named, "symbolic-ref", "HEAD", `refs/heads/${USER}-main`);
    const dest = join(home, "..", "dest");
    const result = await injector
      .executeWithSecret(
        {
          type: "git",
          operation: "clone",
          repository: `http://127.0.0.1:${String(server.port)}/named.git`,
          working_directory: dest,
        },
        SECRET,
        policy(),
        undefined,
      )
      .then(
        (r) => r,
        (e: unknown) => (e instanceof VaultError ? e.code : "threw"),
      );
    expect(exitOf(result)).toBe(0);
    const onBranch = (() => {
      try {
        return git(dest, "symbolic-ref", "--short", "HEAD").trim() === `${USER}-main`;
      } catch {
        return false;
      }
    })();
    expect(onBranch).toBe(true);
    expect(oid(dest, "HEAD")).toBe(oid(named, `refs/heads/${USER}-main`));
    expect(JSON.stringify(result).includes(USER)).toBe(false);
    expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
  });

  it("a failed probe's result is returned redacted: a pull in a directory that is no repository", async () => {
    const plain = join(home, "plain");
    quiet(() => mkdirSync(plain));
    quiet(() => writeFileSync(join(plain, ".git"), "gitdir: missing\n"));
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    const outcome = await audited
      .executeWithSecret(
        { type: "git", operation: "pull", repository: url(), working_directory: plain },
        SECRET,
        policy(),
        undefined,
        "secret-1",
      )
      .then(
        (r) => r,
        (e: unknown) => (e instanceof VaultError ? e.code : "threw"),
      );
    const returned = typeof outcome === "object";
    expect(returned).toBe(true);
    const result = outcome as GitResult;
    expect(result.exit_code === 0).toBe(false);
    expect(JSON.stringify(result).includes(USER)).toBe(false);
    expect(result.stderr.includes("[REDACTED]")).toBe(true);
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail.sanitized).toBe(true);
    expect(JSON.stringify(log.mock.calls).includes(USER)).toBe(false);
  });

  describe("the clone reads the remote's HEAD through the parse seam (F2-E10, W7)", () => {
    const log = vi.fn();
    let own: Listener | undefined;
    const traces = ["GIT_TRACE", "GIT_TRACE_PACKET"];
    const savedTraces: Record<string, string | undefined> = {};
    const dest = () => join(home, "..", "dest");
    const at = (port: number, repoPath: string) => `http://127.0.0.1:${String(port)}/${repoPath}`;

    beforeEach(() => {
      log.mockReset();
      for (const key of traces) savedTraces[key] = process.env[key];
    });

    afterEach(async () => {
      for (const key of traces) {
        const value = savedTraces[key];
        if (value === undefined) Reflect.deleteProperty(process.env, key);
        else process.env[key] = value;
      }
      const listener = own;
      own = undefined;
      if (listener !== undefined) await listener.close();
    });

    function bareRepo(repoDir: string): string {
      const dir = join(srv, repoDir);
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      git(srv, "clone", "-q", "--bare", seed, repoDir);
      return dir;
    }

    function onBranch(dir: string, branch: string): boolean {
      try {
        return git(dir, "symbolic-ref", "--short", "HEAD").trim() === branch;
      } catch {
        return false;
      }
    }

    function headIs(dir: string, id: string): boolean {
      try {
        return git(dir, "rev-parse", "--verify", "-q", "HEAD").trim() === id;
      } catch {
        return false;
      }
    }

    async function clone(
      repository: string,
      secret: Uint8Array,
      port: number,
      extra: { timeout_ms?: number; env_allowlist?: string[] } = {},
    ): Promise<GitResult | string> {
      return new GitInjector({ log } as unknown as AuditLogger)
        .executeWithSecret(
          {
            type: "git",
            operation: "clone",
            repository,
            working_directory: dest(),
            ...(extra.timeout_ms === undefined ? {} : { timeout_ms: extra.timeout_ms }),
          },
          secret,
          {
            ...policy(),
            url_allowlist: [`http://127.0.0.1:${String(port)}/*`],
            env_allowlist: extra.env_allowlist ?? [],
          },
          undefined,
          "secret-1",
        )
        .then(
          (r) => r,
          (e: unknown) => (e instanceof VaultError ? e.code : "threw"),
        );
    }

    it("a clone whose remote HEAD names a branch carrying the credential's user name, with main at the same commit and no master, lands on that branch", async () => {
      const named = bareRepo("user-head.git");
      git(named, "branch", `${USER}-main`, "main");
      git(named, "symbolic-ref", "HEAD", `refs/heads/${USER}-main`);
      const result = await clone(at(server.port, "user-head.git"), SECRET, server.port);
      expect(exitOf(result)).toBe(0);
      expect(onBranch(dest(), `${USER}-main`)).toBe(true);
      expect(JSON.stringify(result).includes(USER)).toBe(false);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(USER)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(TOKEN)).toBe(false);
    });

    it("a clone of a remote whose HEAD is detached, under a user name that occurs inside HEAD's object id, checks out that object id", async () => {
      const detached = bareRepo("detached-head.git");
      const head = oid(detached, "main");
      git(detached, "update-ref", "--no-deref", "HEAD", head);
      const user = head.slice(0, 3);
      own = await startGitSmartHttp({
        git: GIT as string,
        projectRoot: srv,
        user,
        token: TOKEN,
        env: gitEnv,
      });
      const result = await clone(
        at(own.port, "detached-head.git"),
        new Uint8Array(Buffer.from(`${user}:${TOKEN}`)),
        own.port,
      );
      expect(exitOf(result)).toBe(0);
      expect(headIs(dest(), head)).toBe(true);
      expect(JSON.stringify(result).includes(user)).toBe(false);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(TOKEN)).toBe(false);
    });

    it("a clone whose remote HEAD names a branch carrying the credential's token, with master at the same commit, lands on master: the token stays redacted inside the parse", async () => {
      const tokened = bareRepo("token-head.git");
      git(tokened, "branch", "master", "main");
      git(tokened, "branch", `${TOKEN}-main`, "main");
      git(tokened, "symbolic-ref", "HEAD", `refs/heads/${TOKEN}-main`);
      const result = await clone(at(server.port, "token-head.git"), SECRET, server.port);
      expect(exitOf(result)).toBe(0);
      expect(onBranch(dest(), "master")).toBe(true);
      expect(JSON.stringify(result).includes(USER)).toBe(false);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(USER)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(TOKEN)).toBe(false);
    });

    it("a clone under a credential whose token is its user half, its remote HEAD naming a branch carrying the token with master at the same commit, lands on master: the token stays redacted inside the parse (C-15)", async () => {
      const tokened = bareRepo("user-token-head.git");
      git(tokened, "branch", "master", "main");
      git(tokened, "branch", `${TOKEN}-main`, "main");
      git(tokened, "symbolic-ref", "HEAD", `refs/heads/${TOKEN}-main`);
      own = await startGitSmartHttp({
        git: GIT as string,
        projectRoot: srv,
        user: TOKEN,
        token: "x-oauth-basic",
        env: gitEnv,
      });
      const result = await clone(
        at(own.port, "user-token-head.git"),
        new Uint8Array(Buffer.from(`${TOKEN}:x-oauth-basic`)),
        own.port,
      );
      expect(exitOf(result)).toBe(0);
      expect(onBranch(dest(), "master")).toBe(true);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(TOKEN)).toBe(false);
    });

    it("a clone whose remote-HEAD read fails returns it through the full redaction: neither the result nor the audit row carries the user name or the token", async () => {
      const result = await clone(at(server.port, `${USER}-missing.git`), SECRET, server.port);
      expect(typeof result === "object").toBe(true);
      const failed = result as GitResult;
      expect(failed.exit_code === 0).toBe(false);
      expect(failed.stderr.includes("[REDACTED]")).toBe(true);
      expect(JSON.stringify(result).includes(USER)).toBe(false);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
      expect(row.detail.sanitized).toBe(true);
      expect(JSON.stringify(log.mock.calls).includes(USER)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(TOKEN)).toBe(false);
    });

    it("a clone whose remote-HEAD read exceeds the step's deadline returns it through the full redaction: neither the result nor the failed audit row carries the user name or the token", async () => {
      const stall = join(home, "..", "stall.cjs");
      quiet(() =>
        writeFileSync(
          stall,
          "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10_000);\n",
        ),
      );
      own = await startGitSmartHttp({
        git: process.execPath,
        projectRoot: srv,
        user: USER,
        token: TOKEN,
        env: { ...gitEnv, NODE_OPTIONS: `--require="${stall.replaceAll("\\", "/")}"` },
      });
      process.env.GIT_TRACE = "1";
      const result = await clone(at(own.port, `${USER}-stalled.git`), SECRET, own.port, {
        timeout_ms: 5_000,
        env_allowlist: ["GIT_TRACE"],
      });
      expect(typeof result === "object").toBe(true);
      const stalled = result as GitResult;
      expect(stalled.timed_out === true).toBe(true);
      expect(stalled.error === ErrorCode.PROCESS_TIMEOUT).toBe(true);
      expect(JSON.stringify(result).includes(USER)).toBe(false);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      const row = log.mock.calls.at(-1)?.[0] as { success: boolean };
      expect(row.success).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(USER)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(TOKEN)).toBe(false);
    });

    it("a clone whose remote-HEAD read passes the output cap parses the seam's copy: a default branch named with the credential's user name is learned, and neither the result nor the audit row carries the user name or the token (C-16)", async () => {
      const filled = bareRepo("filled-head.git");
      git(filled, "branch", `${USER}-main`, "main");
      git(filled, "symbolic-ref", "HEAD", `refs/heads/${USER}-main`);
      const head = oid(filled, "main");
      const lines = git(filled, "for-each-ref", "--format=%(objectname) %(refname)")
        .split("\n")
        .filter((line) => line !== "");
      for (let i = 0; i < 5_000; i++) {
        lines.push(`${head} refs/fill/${String(i).padStart(5, "0")}-${"x".repeat(200)}`);
      }
      lines.sort((a, b) => (a.slice(a.indexOf(" ")) < b.slice(b.indexOf(" ")) ? -1 : 1));
      quiet(() =>
        writeFileSync(
          join(filled, "packed-refs"),
          `# pack-refs with: peeled fully-peeled sorted \n${lines.join("\n")}\n`,
        ),
      );
      const fillerCount = git(filled, "for-each-ref", "--format=x", "refs/fill/")
        .split("\n")
        .filter((line) => line === "x").length;
      expect(fillerCount === 5_000).toBe(true);
      process.env.GIT_TRACE_PACKET = "1";
      const result = await clone(at(server.port, "filled-head.git"), SECRET, server.port, {
        env_allowlist: ["GIT_TRACE_PACKET"],
      });
      expect(exitOf(result)).toBe(0);
      expect(onBranch(dest(), `${USER}-main`)).toBe(true);
      expect(JSON.stringify(result).includes(USER)).toBe(false);
      expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(USER)).toBe(false);
      expect(JSON.stringify(log.mock.calls).includes(TOKEN)).toBe(false);
    });
  });
});
