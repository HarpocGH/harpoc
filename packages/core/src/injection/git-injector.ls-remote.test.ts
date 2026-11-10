import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { GitAction, InjectionPolicy } from "@harpoc/shared";
import { MAX_PROCESS_OUTPUT_BYTES } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { startGitSmartHttp } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { GitInjector } from "./git-injector.js";

/**
 * M6 (B9): an ls-remote is one credential-bearing step against an empty relay
 * the vault wrote and no local step; the remote's listing comes back through
 * the spawn seam's redaction and output cap — real git against a smart-HTTP
 * listener on 127.0.0.1 that answers every request 401 without the credential.
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

describeGit("Git ls-remote through an empty relay — real git over smart HTTP (M6)", () => {
  const injector = new GitInjector(null);
  let root: string;
  let srv: string;
  let vaultTemp: string;
  let server: Listener;
  let gitEnv: NodeJS.ProcessEnv;
  const saved: Record<string, string | undefined> = {};

  function git(cwd: string, ...args: string[]): string {
    return execFileSync(GIT as string, args, { cwd, env: gitEnv, encoding: "utf8" });
  }

  function quiet<T>(run: () => T): T {
    try {
      return run();
    } catch {
      throw new Error("a step on a credential-bearing argument failed");
    }
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
    };
  }

  function lsRemote(repo: string, rest: Omit<GitAction, "type" | "operation" | "repository">) {
    return injector.executeWithSecret(
      { type: "git", operation: "ls-remote", repository: url(repo), ...rest },
      SECRET,
      policy(),
      undefined,
    );
  }

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-ls-remote-"));
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
    const seed = join(root, "seed");
    git(root, "init", "-q", "-b", "main", seed);
    writeFileSync(join(seed, "f.txt"), "1\n");
    git(seed, "add", "f.txt");
    git(seed, "commit", "-q", "-m", "c1");
    git(seed, "tag", "-a", "-m", "annotated", "v1");
    quiet(() => git(seed, "branch", TOKEN));
    git(srv, "clone", "-q", "--bare", seed, "repo.git");
    git(srv, "init", "-q", "--bare", "-b", "main", "empty.git");
    git(srv, "clone", "-q", "--bare", seed, "many.git");
    const head = git(seed, "rev-parse", "HEAD").trim();
    const lines = Array.from(
      { length: 9000 },
      (_, i) => `${head} refs/heads/b/${String(i).padStart(5, "0")}-${"x".repeat(90)}\n`,
    );
    const packed = join(srv, "many.git", "packed-refs");
    const kept = readFileSync(packed, "utf8").split("\n").slice(1).join("\n");
    writeFileSync(packed, `# pack-refs with: peeled fully-peeled \n${kept}${lines.join("")}`);
    const seed256 = join(root, "seed256");
    git(root, "init", "-q", "-b", "main", "--object-format=sha256", seed256);
    writeFileSync(join(seed256, "f.txt"), "1\n");
    git(seed256, "add", "f.txt");
    git(seed256, "commit", "-q", "-m", "c1");
    git(srv, "init", "-q", "--bare", "-b", "main", "--object-format=sha256", "sha256.git");
    git(seed256, "push", "-q", join(srv, "sha256.git"), "main");
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

  it("lists the remote's refs, the remote HEAD's branch under --symref, branches only under --heads", async () => {
    const head = git(join(srv, "repo.git"), "rev-parse", "main").trim();
    const all = await lsRemote("repo.git", { args: ["--symref"] });
    expect(all.exit_code, all.stderr).toBe(0);
    expect(all.operation).toBe("ls-remote");
    expect(all.stdout).toContain("ref: refs/heads/main\tHEAD\n");
    expect(all.stdout).toContain(`${head}\trefs/heads/main\n`);
    expect(all.stdout).toContain("\trefs/tags/v1^{}\n");
    const heads = await lsRemote("repo.git", { args: ["--heads", "--refs"] });
    expect(heads.exit_code, heads.stderr).toBe(0);
    expect(heads.stdout).not.toContain("refs/tags/");
  });

  it("a ref name carrying the credential comes back redacted", async () => {
    const result = await lsRemote("repo.git", {});
    expect(result.exit_code, result.stderr).toBe(0);
    expect(result.stdout.includes("\trefs/heads/[REDACTED]\n")).toBe(true);
    expect(JSON.stringify(result).includes(TOKEN)).toBe(false);
  });

  it("--exit-code on an empty remote is exit 2 with no error: a successful use", async () => {
    const result = await lsRemote("empty.git", { args: ["--exit-code"] });
    expect(result.exit_code).toBe(2);
    expect(result.error).toBeUndefined();
    expect(result.stdout).toBe("");
  });

  it("lists a sha256 remote through the sha1 relay: its object ids are 64 hex characters", async () => {
    const result = await lsRemote("sha256.git", {});
    expect(result.exit_code, result.stderr).toBe(0);
    const listed = result.stdout.split("\n").filter(Boolean);
    expect(listed.length).toBeGreaterThan(0);
    expect(listed.every((line) => /^[0-9a-f]{64}\t/.test(line))).toBe(true);
  });

  it("a listing past the output cap keeps its head and reports truncated", async () => {
    const result = await lsRemote("many.git", { args: ["--heads"] });
    expect(result.exit_code, result.stderr).toBe(0);
    expect(result.truncated).toBe(true);
    expect(Buffer.byteLength(result.stdout)).toBeLessThanOrEqual(MAX_PROCESS_OUTPUT_BYTES);
    expect(result.stdout.split("\n")[0]).toMatch(/^[0-9a-f]{40}\trefs\/heads\//);
  });
});
