import { execFileSync } from "node:child_process";
import {
  existsSync,
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
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import { GitInjector } from "./git-injector.js";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";

/**
 * S1 (C1.2 fix round 1, F-1): a clone's credential-bearing steps run against a
 * vault-written relay repository and the caller's clone is made from it by a
 * credential-free local step, so no credential-bearing git reads configuration
 * in the destination. These cases pin that today's clone semantics survive the
 * relay, on real git against a smart-HTTP listener on 127.0.0.1 that answers
 * every request 401 without the Basic credential.
 */

const GIT = resolveSupportedGit();
// Skipped where no supported git resolves.
const describeGit = describe.skipIf(GIT === null);

const USER = "vaultuser";
const TOKEN = "S3CRET-TOKEN-xyz";
const SECRET = new Uint8Array(Buffer.from(`${USER}:${TOKEN}`));

it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no supported git resolves',
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
      proxy: false,
      ssh_agent_socket: false,
      local_dirs: [],
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
    expectAbsent(JSON.stringify(result), TOKEN);
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

  it("a relative destination is cloned below the process's directory, and git's output names the resolved path", async () => {
    const savedCwd = process.cwd();
    process.chdir(out);
    let result;
    try {
      result = await clone("repo.git", { working_directory: "relative-clone" });
    } finally {
      process.chdir(savedCwd);
    }
    expect(result.exit_code, result.stderr).toBe(0);
    const resolved = join(realpathSync.native(out), "relative-clone");
    expect(result.stderr).toContain(`Cloning into '${resolved}'...`);
    expect(readdirSync(out)).toEqual(["relative-clone"]);
  });

  // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
  // `..` behind a link from the link's target.
  it.skipIf(process.platform === "win32")(
    "a destination spelled through a link and `..` is written where the system resolves the spelling, and nowhere else",
    async () => {
      mkdirSync(join(out, "elsewhere", "deep"), { recursive: true });
      mkdirSync(join(out, "agent"));
      const link = join(out, "agent", "link");
      symlinkSync(join(out, "elsewhere", "deep"), link, "dir");
      const result = await clone("repo.git", { working_directory: `${link}/../clone` });
      expect(result.exit_code, result.stderr).toBe(0);
      const resolved = join(realpathSync.native(join(out, "elsewhere")), "clone");
      expect(result.stderr).toContain(`Cloning into '${resolved}'...`);
      expect(readdirSync(join(out, "agent"))).toEqual(["link"]);
      expect(readdirSync(join(out, "elsewhere")).sort()).toEqual(["clone", "deep"]);
      expect(git(join(out, "elsewhere", "clone"), "branch", "--show-current").trim()).toBe("main");
    },
  );

  // A symbolic link needs a privilege on win32. Plain git 2.39 writes a bare clone through a
  // link that leads nowhere, into the link's target.
  it.skipIf(process.platform === "win32").each(["--bare", "--mirror"])(
    "a %s clone whose destination is a link that leads nowhere is refused, and nothing is made at the link's target",
    async (option) => {
      mkdirSync(join(out, "elsewhere"));
      const link = join(out, "link");
      symlinkSync(join(out, "elsewhere", "planted"), link, "dir");
      const err = await expectVaultError(
        () => clone("repo.git", { args: [option], working_directory: link }),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(err.message).toBe("git working directory is inside a directory the vault protects");
      expect(readdirSync(join(out, "elsewhere"))).toEqual([]);
      expect(readdirSync(out).sort()).toEqual(["elsewhere", "link"]);
    },
  );

  // A symbolic link needs a privilege on win32. Darwin's realpath takes a `..` off the name of
  // a file where Linux answers ENOTDIR: on either, the link behind it is not handed to git.
  it.skipIf(process.platform === "win32")(
    "a --bare clone whose destination is a link that leads nowhere, spelled behind a file and `..`, is refused, and nothing is made at the link's target",
    async () => {
      mkdirSync(join(out, "elsewhere"));
      writeFileSync(join(out, "file"), "");
      symlinkSync(join(out, "elsewhere", "planted"), join(out, "link"), "dir");
      await expectVaultError(
        () => clone("repo.git", { args: ["--bare"], working_directory: `${out}/file/../link` }),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(readdirSync(join(out, "elsewhere"))).toEqual([]);
      expect(readdirSync(out).sort()).toEqual(["elsewhere", "file", "link"]);
    },
  );

  // A symbolic link needs a privilege on win32. Off win32 the system refuses to read a
  // spelling at its length limit, 1024 bytes on macOS and 4096 on Linux, the link included.
  it.skipIf(process.platform === "win32").each([1024, 4096])(
    "a --bare clone whose destination is a link that leads nowhere, behind a spelling of %i characters of `.` steps, is refused, and nothing is made at the link's target",
    async (length) => {
      mkdirSync(join(out, "elsewhere"));
      const room = length - out.length - 1 - "link".length;
      const name = room % 2 === 0 ? "link" : "links";
      symlinkSync(join(out, "elsewhere", "planted"), join(out, name), "dir");
      const spelled = `${out}/${"./".repeat(Math.floor(room / 2))}${name}`;
      expect(spelled).toHaveLength(length);
      await expectVaultError(
        () => clone("repo.git", { args: ["--bare"], working_directory: spelled }),
        ErrorCode.LOCAL_PATH_NOT_ALLOWED,
      );
      expect(readdirSync(join(out, "elsewhere"))).toEqual([]);
      expect(readdirSync(out).sort()).toEqual(["elsewhere", name]);
    },
  );
});
