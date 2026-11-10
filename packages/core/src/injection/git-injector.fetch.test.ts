import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { GitInjector } from "./git-injector.js";
import { expectVaultError } from "@harpoc/test-utils";

/**
 * M6 (B9): a fetch runs its one credential-bearing step into a vault-written
 * relay and lands the result in the caller's tree by a credential-free local
 * `fetch` — branches under `refs/remotes/<remote>/`, tags under `refs/tags/` —
 * on real git against a smart-HTTP listener on 127.0.0.1 that answers every
 * request 401 without the Basic credential.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
// Skipped where git does not resolve.
const describeGit = describe.skipIf(GIT === null);

const USER = "vaultuser";
const TOKEN = "S3CRET-TOKEN-xyz";
const SECRET = new Uint8Array(Buffer.from(`${USER}:${TOKEN}`));

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

describeGit("Git fetch through the relay — real git over smart HTTP (M6)", () => {
  const injector = new GitInjector(null);
  let root: string;
  let srv: string;
  let seed: string;
  let vaultTemp: string;
  let wd: string;
  let server: Listener;
  let gitEnv: NodeJS.ProcessEnv;
  const saved: Record<string, string | undefined> = {};

  function git(cwd: string, ...args: string[]): string {
    return execFileSync(GIT as string, args, {
      cwd,
      env: gitEnv,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 20_000,
    });
  }

  function quiet<T>(run: () => T): T {
    try {
      return run();
    } catch {
      throw new Error("a step on a credential-bearing argument failed");
    }
  }

  const url = (repo: string) => `http://127.0.0.1:${String(server.port)}/${repo}`;

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

  function fetchThroughInjector(
    rest: Omit<GitAction, "type" | "operation" | "repository" | "working_directory">,
  ) {
    return injector.executeWithSecret(
      {
        type: "git",
        operation: "fetch",
        repository: url("repo.git"),
        working_directory: wd,
        ...rest,
      },
      SECRET,
      policy(),
      undefined,
    );
  }

  const refsOf = (...patterns: string[]) =>
    git(wd, "for-each-ref", "--format=%(refname) %(objectname)", ...patterns)
      .split("\n")
      .filter(Boolean);
  const oid = (dir: string, rev: string) => git(dir, "rev-parse", rev).trim();

  /** The remote moves: main gains a commit tagged v3, `new` appears, `other` is deleted, `side` is rewritten. */
  function moveRemote(): void {
    const bare = join(srv, "repo.git");
    git(seed, "checkout", "-q", "side");
    git(seed, "reset", "-q", "--hard", "main~2");
    writeFileSync(join(seed, "s.txt"), "rewritten\n");
    git(seed, "add", "s.txt");
    git(seed, "commit", "-q", "-m", "side2");
    git(seed, "push", "-q", "-f", bare, "side");
    git(seed, "checkout", "-q", "main");
    writeFileSync(join(seed, "f.txt"), "4\n");
    git(seed, "commit", "-q", "-am", "c4");
    git(seed, "tag", "v3");
    git(seed, "push", "-q", bare, "main", "v3");
    git(seed, "push", "-q", bare, "main~1:refs/heads/new");
    git(bare, "branch", "-D", "other");
  }

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-fetch-"));
    const emptyConfig = join(root, "empty.gitconfig");
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
    srv = join(root, "srv");
    mkdirSync(srv);
  });

  beforeEach(async () => {
    for (const key of ["TMPDIR", "TMP", "TEMP"]) saved[key] = process.env[key];
    const run = mkdtempSync(join(root, "run-"));
    seed = join(run, "seed");
    git(run, "init", "-q", "-b", "main", seed);
    for (const n of ["1", "2", "3"]) {
      writeFileSync(join(seed, "f.txt"), `${n}\n`);
      git(seed, "add", "f.txt");
      git(seed, "commit", "-q", "-m", `c${n}`);
    }
    git(seed, "tag", "v1", "HEAD~2");
    git(seed, "branch", "other", "HEAD~1");
    git(seed, "checkout", "-q", "-b", "side", "HEAD~2");
    writeFileSync(join(seed, "s.txt"), "side\n");
    git(seed, "add", "s.txt");
    git(seed, "commit", "-q", "-m", "side");
    git(seed, "checkout", "-q", "main");
    rmSync(join(srv, "repo.git"), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    git(srv, "clone", "-q", "--bare", seed, "repo.git");
    server = await startGitSmartHttp({
      git: GIT as string,
      projectRoot: srv,
      user: USER,
      token: TOKEN,
      env: gitEnv,
    });
    wd = join(run, "wd");
    git(run, "clone", "-q", join(srv, "repo.git"), wd);
    git(wd, "remote", "set-url", "origin", url("repo.git"));
    git(wd, "branch", "localonly", "main~1");
    git(wd, "tag", "localtag", "main~1");
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

  it("a new branch lands under refs/remotes/origin/, a moved branch moves, a rewritten branch is taken under the +, and the local branches, the checked-out branch and the config stay", async () => {
    const config = readFileSync(join(wd, ".git", "config"));
    const localMain = oid(wd, "main");
    const localOnly = oid(wd, "localonly");
    moveRemote();
    const result = await fetchThroughInjector({});
    expect(result.exit_code, result.stderr).toBe(0);
    expect(result.operation).toBe("fetch");
    const bare = join(srv, "repo.git");
    expect(oid(wd, "refs/remotes/origin/main")).toBe(oid(bare, "main"));
    expect(oid(wd, "refs/remotes/origin/new")).toBe(oid(bare, "new"));
    expect(oid(wd, "refs/remotes/origin/side")).toBe(oid(bare, "side"));
    expect(oid(wd, "refs/tags/v3")).toBe(oid(bare, "v3"));
    expect(refsOf("refs/remotes/origin/other")).toHaveLength(1);
    expect(git(wd, "symbolic-ref", "HEAD").trim()).toBe("refs/heads/main");
    expect(oid(wd, "main")).toBe(localMain);
    expect(oid(wd, "localonly")).toBe(localOnly);
    expect(refsOf("refs/remotes/origin/localonly")).toEqual([]);
    expect(git(wd, "status", "--porcelain")).toBe("");
    expect(readFileSync(join(wd, ".git", "config")).equals(config)).toBe(true);
    expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
    expect(readFileSync(join(wd, ".git", "FETCH_HEAD"), "utf8").includes(TOKEN)).toBe(false);
  });

  it("--prune removes a branch deleted on the remote; a refspec naming one branch prunes nothing else", async () => {
    moveRemote();
    const one = await fetchThroughInjector({ args: ["--prune"], refspecs: ["refs/heads/main"] });
    expect(one.exit_code, one.stderr).toBe(0);
    expect(refsOf("refs/remotes/origin/other")).toHaveLength(1);
    expect(refsOf("refs/remotes/origin/side")).toHaveLength(1);
    expect(refsOf("refs/remotes/origin/new")).toEqual([]);
    const all = await fetchThroughInjector({ args: ["--prune"] });
    expect(all.exit_code, all.stderr).toBe(0);
    expect(refsOf("refs/remotes/origin/other")).toEqual([]);
    expect(refsOf("refs/remotes/origin/new")).toHaveLength(1);
  });

  it("tags: followed into the fetched history by default, none under --no-tags, every one under --tags", async () => {
    moveRemote();
    git(join(srv, "repo.git"), "tag", "far", "side");
    const followed = await fetchThroughInjector({ refspecs: ["refs/heads/main"] });
    expect(followed.exit_code, followed.stderr).toBe(0);
    expect(refsOf("refs/tags/v3")).toHaveLength(1);
    expect(refsOf("refs/tags/far")).toEqual([]);
    git(join(srv, "repo.git"), "tag", "nearer", "main");
    const none = await fetchThroughInjector({ args: ["--no-tags"], refspecs: ["refs/heads/main"] });
    expect(none.exit_code, none.stderr).toBe(0);
    expect(refsOf("refs/tags/nearer", "refs/tags/far")).toEqual([]);
    const all = await fetchThroughInjector({ args: ["--tags"], refspecs: ["refs/heads/main"] });
    expect(all.exit_code, all.stderr).toBe(0);
    expect(refsOf("refs/tags/far")).toHaveLength(1);
    expect(refsOf("refs/tags/localtag")).toHaveLength(1);
  });

  it("refspecs: a branch lands under refs/remotes/origin/, a tag pattern under refs/tags/, a negative refspec excludes", async () => {
    moveRemote();
    const result = await fetchThroughInjector({
      args: ["--no-tags"],
      refspecs: ["+refs/heads/*", "^refs/heads/new", "refs/tags/v3"],
    });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(refsOf("refs/remotes/origin/new")).toEqual([]);
    expect(oid(wd, "refs/remotes/origin/main")).toBe(oid(join(srv, "repo.git"), "main"));
    expect(oid(wd, "refs/tags/v3")).toBe(oid(join(srv, "repo.git"), "v3"));
  });

  it("without the +, a rewritten branch is refused by the local step as git's own fetch refuses it", async () => {
    moveRemote();
    const before = oid(wd, "refs/remotes/origin/side");
    const result = await fetchThroughInjector({ refspecs: ["refs/heads/side"] });
    expect(result.exit_code).not.toBe(0);
    expect(oid(wd, "refs/remotes/origin/side")).toBe(before);
  });

  it("--depth=1 leaves a full tree shallow; --unshallow completes it", async () => {
    moveRemote();
    const shallow = await fetchThroughInjector({ args: ["--depth=1"] });
    expect(shallow.exit_code, shallow.stderr).toBe(0);
    expect(git(wd, "rev-parse", "--is-shallow-repository").trim()).toBe("true");
    const full = await fetchThroughInjector({ args: ["--unshallow"] });
    expect(full.exit_code, full.stderr).toBe(0);
    expect(git(wd, "rev-parse", "--is-shallow-repository").trim()).toBe("false");
    expect(git(wd, "rev-list", "--count", "refs/remotes/origin/main").trim()).toBe("4");
  });

  it("the tree's remote for the repository names the destination (`up.stream/x`)", async () => {
    git(wd, "remote", "rename", "origin", "up.stream/x");
    moveRemote();
    const result = await fetchThroughInjector({ refspecs: ["refs/heads/new"] });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(oid(wd, "refs/remotes/up.stream/x/new")).toBe(oid(join(srv, "repo.git"), "new"));
  });

  it("a `remote.<repository>.fetch` of the tree's config moves and creates no local branch: the local fetch takes the vault's refspecs alone (E-18)", async () => {
    git(wd, "config", `remote.${url("repo.git")}.fetch`, "+refs/heads/*:refs/heads/*");
    git(wd, "checkout", "-q", "-b", "work");
    const localMain = oid(wd, "main");
    const branches = refsOf("refs/heads/");
    moveRemote();
    const result = await fetchThroughInjector({});
    expect(result.exit_code, result.stderr).toBe(0);
    expect(oid(wd, "main")).toBe(localMain);
    expect(refsOf("refs/heads/")).toEqual(branches);
    expect(git(wd, "symbolic-ref", "HEAD").trim()).toBe("refs/heads/work");
    const bare = join(srv, "repo.git");
    expect(oid(wd, "refs/remotes/origin/main")).toBe(oid(bare, "main"));
    expect(oid(wd, "refs/remotes/origin/new")).toBe(oid(bare, "new"));
  });

  it("a tree with no remote on the repository's URL, or two, is refused and left as it was", async () => {
    git(wd, "remote", "set-url", "origin", `${url("repo.git")}/`);
    const before = refsOf();
    const none = await expectVaultError(
      () => fetchThroughInjector({}),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(none.message).toBe(`no remote of the working tree has the URL ${url("repo.git")}`);
    git(wd, "remote", "add", "a", url("repo.git"));
    git(wd, "remote", "add", "b", url("repo.git"));
    const two = await expectVaultError(
      () => fetchThroughInjector({}),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(two.message).toBe(`2 remotes of the working tree have the URL ${url("repo.git")}`);
    expect(refsOf()).toEqual(before);
  });

  it("no hook of the caller's tree runs during the fetch, while git's own fetch runs its reference-transaction hook (N11)", async () => {
    const marker = join(root, `hook-${String(Date.now())}`);
    const hook = join(wd, ".git", "hooks", "reference-transaction");
    writeFileSync(hook, `#!/bin/sh\necho ran >> "${marker.replace(/\\/g, "/")}"\ncat >/dev/null\n`);
    chmodSync(hook, 0o755);
    moveRemote();
    const result = await fetchThroughInjector({ args: ["--auto-maintenance"] });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(existsSync(marker)).toBe(false);
    git(wd, "fetch", "-q", join(srv, "repo.git"), "+refs/heads/main:refs/remotes/control/main");
    expect(existsSync(marker)).toBe(true);
  });

  it("a repository URL carrying the credential's username is still found as the tree's remote (RX-B9-14)", async () => {
    moveRemote();
    quiet(() =>
      rmSync(join(srv, USER), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }),
    );
    quiet(() => git(srv, "clone", "-q", "--bare", join(srv, "repo.git"), join(USER, "repo.git")));
    const userUrl = url(`${USER}/repo.git`);
    quiet(() => git(wd, "remote", "set-url", "origin", userUrl));
    const outcome = await injector
      .executeWithSecret(
        { type: "git", operation: "fetch", repository: userUrl, working_directory: wd },
        SECRET,
        policy(),
        undefined,
      )
      .then(
        (r) => r.exit_code,
        (e: unknown) => (e instanceof VaultError ? e.code : "threw"),
      );
    expect(outcome).toBe(0);
    const remoteNew = quiet(() => oid(join(srv, USER, "repo.git"), "new"));
    expect(oid(wd, "refs/remotes/origin/new")).toBe(remoteNew);
  });

  it("a remote whose name carries the credential's username is found like any other (RG-6)", async () => {
    quiet(() => git(wd, "remote", "rename", "origin", `${USER}-fork`));
    moveRemote();
    const result = await fetchThroughInjector({});
    expect(result.exit_code).toBe(0);
    const landed = quiet(() => oid(wd, `refs/remotes/${USER}-fork/new`));
    expect(landed).toBe(oid(join(srv, "repo.git"), "new"));
    expect(JSON.stringify(result).includes(USER)).toBe(false);
    expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
  });

  it("a submodule whose pointer the fetched commits move is left to the caller: the local fetch does not recurse (RX-B9-16)", async () => {
    const subSeed = join(root, `sub-seed-${String(Date.now())}`);
    git(root, "init", "-q", "-b", "main", subSeed);
    writeFileSync(join(subSeed, "a.txt"), "1\n");
    git(subSeed, "add", "a.txt");
    git(subSeed, "commit", "-q", "-m", "s1");
    rmSync(join(srv, "sub.git"), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    git(srv, "clone", "-q", "--bare", subSeed, "sub.git");
    const subUrl = pathToFileURL(join(srv, "sub.git")).href;
    git(seed, "-c", "protocol.file.allow=always", "submodule", "add", "-q", subUrl, "sub");
    git(seed, "commit", "-q", "-m", "add sub");
    git(seed, "push", "-q", join(srv, "repo.git"), "main");
    git(wd, "pull", "-q", "--no-rebase", join(srv, "repo.git"), "main");
    git(wd, "-c", "protocol.file.allow=always", "submodule", "update", "-q", "--init");
    git(join(wd, "sub"), "remote", "set-url", "origin", "https://127.0.0.1:9/sub.git");
    git(wd, "config", "submodule.sub.url", "https://127.0.0.1:9/sub.git");
    writeFileSync(join(subSeed, "a.txt"), "2\n");
    git(subSeed, "commit", "-q", "-am", "s2");
    git(subSeed, "push", "-q", join(srv, "sub.git"), "main");
    git(join(seed, "sub"), "-c", "protocol.file.allow=always", "pull", "-q", "origin", "main");
    git(seed, "add", "sub");
    git(seed, "commit", "-q", "-m", "move sub");
    git(seed, "push", "-q", join(srv, "repo.git"), "main");
    const result = await fetchThroughInjector({});
    expect(result.exit_code, result.stderr).toBe(0);
    expect(result.stderr).not.toContain("not allowed");
    expect(oid(wd, "refs/remotes/origin/main")).toBe(oid(join(srv, "repo.git"), "main"));
  });
});
