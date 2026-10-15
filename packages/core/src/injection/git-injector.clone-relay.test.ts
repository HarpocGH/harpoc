import { execFileSync } from "node:child_process";
import {
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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { GitAction, InjectionPolicy } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { GitInjector } from "./git-injector.js";

/**
 * S1 (C1.2 fix round 1, F-1): a clone's credential-bearing steps run against a
 * vault-written relay repository and the caller's clone is made from it by a
 * credential-free local step, so no credential-bearing git reads configuration
 * in the destination. These cases pin that today's clone semantics survive the
 * relay, on real git against a smart-HTTP listener on 127.0.0.1 that answers
 * every request 401 without the Basic credential.
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

describeGit("Git clone through the relay — today's clone semantics on real git (S1, F-1)", () => {
  const injector = new GitInjector(null);
  let root: string;
  let srv: string;
  let vaultTemp: string;
  let out: string;
  let server: Listener;
  let gitEnv: NodeJS.ProcessEnv;
  const saved: Record<string, string | undefined> = {};

  function git(cwd: string, ...args: string[]): string {
    return execFileSync(GIT as string, args, { cwd, env: gitEnv, encoding: "utf8" });
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
    };
  }

  function clone(repo: string, rest: Omit<GitAction, "type" | "operation" | "repository">) {
    return injector.executeWithSecret(
      { type: "git", operation: "clone", repository: url(repo), ...rest },
      SECRET,
      policy(),
      undefined,
    );
  }

  /** A seed repository with three commits on main, a branch `other` and a tag `v1`. */
  function seed(dir: string, objectFormat: "sha1" | "sha256"): void {
    git(root, "init", "-q", `--object-format=${objectFormat}`, "-b", "main", dir);
    for (const n of ["1", "2", "3"]) {
      writeFileSync(join(dir, "f.txt"), `${n}\n`);
      git(dir, "add", "f.txt");
      git(dir, "commit", "-q", "-m", `c${n}`);
    }
    git(dir, "tag", "v1", "HEAD~2");
    git(dir, "branch", "other", "HEAD~1");
  }

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-clone-relay-"));
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
    seed(join(root, "seed"), "sha1");
    git(srv, "clone", "-q", "--bare", join(root, "seed"), "repo.git");
    git(srv, "clone", "-q", "--bare", join(root, "seed"), "detached.git");
    const otherTip = git(join(srv, "detached.git"), "rev-parse", "other").trim();
    git(join(srv, "detached.git"), "update-ref", "--no-deref", "HEAD", otherTip);
    git(srv, "init", "-q", "--bare", "-b", "devel", "empty.git");
    seed(join(root, "seed256"), "sha256");
    git(srv, "clone", "-q", "--bare", join(root, "seed256"), "sha256.git");
    server = await startGitSmartHttp({
      git: GIT as string,
      projectRoot: srv,
      user: USER,
      token: TOKEN,
      env: gitEnv,
    });
  });

  beforeEach(() => {
    for (const key of ["TMPDIR", "TMP", "TEMP"]) saved[key] = process.env[key];
    vaultTemp = mkdtempSync(join(root, "vault-tmp-"));
    process.env.TMPDIR = vaultTemp;
    process.env.TMP = vaultTemp;
    process.env.TEMP = vaultTemp;
    out = mkdtempSync(join(root, "out-"));
  });

  afterEach(() => {
    for (const key of ["TMPDIR", "TMP", "TEMP"]) {
      const value = saved[key];
      if (value === undefined) Reflect.deleteProperty(process.env, key);
      else process.env[key] = value;
    }
    expect(readdirSync(vaultTemp)).toEqual([]);
  });

  afterAll(async () => {
    try {
      if (server !== undefined) await server.close();
    } finally {
      if (root !== undefined)
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("without working_directory: the directory git names after the URL, origin the real URL, the remote's HEAD branch checked out, every branch and the tag", async () => {
    const savedCwd = process.cwd();
    process.chdir(out);
    let result;
    try {
      result = await clone("repo.git", {});
    } finally {
      process.chdir(savedCwd);
    }
    expect(result.exit_code, result.stderr).toBe(0);
    expect(readdirSync(out)).toEqual(["repo"]);
    const dest = join(out, "repo");
    expect(git(dest, "config", "remote.origin.url").trim()).toBe(url("repo.git"));
    expect(git(dest, "branch", "--show-current").trim()).toBe("main");
    expect(git(dest, "symbolic-ref", "refs/remotes/origin/HEAD").trim()).toBe(
      "refs/remotes/origin/main",
    );
    expect(
      git(dest, "for-each-ref", "--format=%(refname)", "refs/remotes", "refs/tags")
        .split("\n")
        .filter(Boolean),
    ).toEqual([
      "refs/remotes/origin/HEAD",
      "refs/remotes/origin/main",
      "refs/remotes/origin/other",
      "refs/tags/v1",
    ]);
    expect(git(dest, "rev-parse", "--is-shallow-repository").trim()).toBe("false");
    expect(readFileSync(join(dest, ".git", "config"), "utf8")).not.toContain("harpoc-git-relay");
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  it("--branch checks out the named branch", async () => {
    const dest = join(out, "b");
    const result = await clone("repo.git", {
      args: ["--branch", "other"],
      working_directory: dest,
    });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(git(dest, "branch", "--show-current").trim()).toBe("other");
    expect(git(dest, "config", "remote.origin.url").trim()).toBe(url("repo.git"));
  });

  it("--depth gives a shallow single-branch clone, as git's own does", async () => {
    const dest = join(out, "d");
    const result = await clone("repo.git", { args: ["--depth", "1"], working_directory: dest });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(git(dest, "rev-parse", "--is-shallow-repository").trim()).toBe("true");
    expect(git(dest, "rev-list", "--count", "HEAD").trim()).toBe("1");
    expect(git(dest, "config", "remote.origin.fetch").trim()).toBe(
      "+refs/heads/main:refs/remotes/origin/main",
    );
  });

  it("--single-branch --no-tags fetch one branch and no tag", async () => {
    const dest = join(out, "s");
    const result = await clone("repo.git", {
      args: ["--single-branch", "--no-tags"],
      working_directory: dest,
    });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(
      git(dest, "for-each-ref", "--format=%(refname)", "refs/remotes", "refs/tags")
        .split("\n")
        .filter(Boolean),
    ).toEqual(["refs/remotes/origin/HEAD", "refs/remotes/origin/main"]);
    expect(git(dest, "config", "remote.origin.tagOpt").trim()).toBe("--no-tags");
  });

  it("a detached remote HEAD checks out what git's own clone checks out", async () => {
    const direct = join(out, "direct");
    git(out, "clone", "-q", join(srv, "detached.git"), direct);
    const dest = join(out, "relayed");
    const result = await clone("detached.git", { working_directory: dest });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(git(dest, "branch", "--show-current").trim()).toBe(
      git(direct, "branch", "--show-current").trim(),
    );
    expect(git(dest, "rev-parse", "HEAD").trim()).toBe(git(direct, "rev-parse", "HEAD").trim());
  });

  it("an empty remote clones with exit 0 onto master (the remote's unborn branch is not learned — C1.2 fix round 1, Q1)", async () => {
    const dest = join(out, "e");
    const result = await clone("empty.git", { working_directory: dest });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(git(dest, "symbolic-ref", "HEAD").trim()).toBe("refs/heads/master");
    expect(git(dest, "config", "remote.origin.url").trim()).toBe(url("empty.git"));
  });

  it("a sha256 remote gives a sha256 clone", async () => {
    const dest = join(out, "h");
    const result = await clone("sha256.git", { working_directory: dest });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(git(dest, "rev-parse", "--show-object-format").trim()).toBe("sha256");
    expect(git(dest, "branch", "--show-current").trim()).toBe("main");
    expect(existsSync(join(dest, "f.txt"))).toBe(true);
  });
});
