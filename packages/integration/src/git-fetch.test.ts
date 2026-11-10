import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { GitResult, UseSecretAction } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startGitSmartHttp } from "./helpers/git-smart-http-plain.js";
import type { GitSmartHttp } from "./helpers/git-smart-http-plain.js";
import { tierRequired } from "./helpers/platform-tiers.js";
import { expectVaultError } from "@harpoc/test-utils";

/**
 * M6 (deployment model B, tranche B9): a `fetch` through the vault on a real
 * engine with the real git, against a smart-HTTP remote on 127.0.0.1 that
 * answers only the Basic credential the secret holds. The credential-bearing
 * step fetches into the vault's relay; the caller's tree sees a credential-free
 * local fetch, which lands the remote's branches under `refs/remotes/origin/*`
 * (the tree's own remote for the repository) and moves neither the checked-out
 * branch nor a working file. `--prune` and `--tags` ride `args`. The rows share
 * one tree and run in order.
 *
 * Every git run here is asynchronous: the smart-HTTP fixture shares this
 * process's event loop, so a synchronous git would block its own transfer.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
const describeGit = describe.skipIf(GIT === null);
const PASSWORD = "integration-test-pw";
const GIT_TIMEOUT_MS = 30_000;
const USER = "fetch_user";
const TOKEN = "fetch-token-7c6b5a49e3";

// A leg that exports the ssh-live tier ships git as well (TM-11): where git does not resolve
// on such a leg, this guard fails the file instead of letting the suite below skip silently.
it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

describeGit("Git context — fetch through the vault (M6)", () => {
  let root: string;
  let bare: string;
  let seed: string;
  let wt: string;
  let server: GitSmartHttp;
  let repoUrl: string;
  let vault: TestVault;
  let handle: string;
  let client: DirectClient;
  let gitEnv: NodeJS.ProcessEnv;
  let configBefore: Buffer;
  let headBefore: string;
  let mainBefore: string;
  const results: GitResult[] = [];

  function git(cwd: string, ...args: string[]): Promise<string> {
    return new Promise((done, fail) => {
      execFile(
        GIT as string,
        args,
        { cwd, env: gitEnv, encoding: "utf8", timeout: GIT_TIMEOUT_MS },
        (err, stdout, stderr) => {
          if (err) fail(new Error(`git ${args.join(" ")}: ${err.message}\n${stderr}`));
          else done(stdout);
        },
      );
    });
  }

  const refOf = async (cwd: string, ref: string): Promise<string> =>
    (await git(cwd, "rev-parse", ref)).trim();

  const refNames = async (cwd: string): Promise<string[]> =>
    (await git(cwd, "for-each-ref", "--format=%(refname)")).split(/\r?\n/).filter(Boolean);

  const refListing = async (cwd: string): Promise<string[]> =>
    (await git(cwd, "for-each-ref", "--format=%(objectname) %(refname)"))
      .split(/\r?\n/)
      .filter(Boolean);

  function filesUnder(dir: string): string[] {
    return readdirSync(dir).flatMap((entry) => {
      const path = join(dir, entry);
      return statSync(path).isDirectory() ? filesUnder(path) : [path];
    });
  }

  async function fetchThroughVault(args?: string[]): Promise<GitResult> {
    const result = await client.useSecret(handle, {
      type: "git",
      operation: "fetch",
      repository: repoUrl,
      working_directory: wt,
      ...(args === undefined ? {} : { args }),
    });
    if (result.type !== "git") throw new Error("expected a git result");
    results.push(result);
    return result;
  }

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-fetch-"));
    const emptyConfig = join(root, "gitconfig");
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

    bare = join(root, "repo.git");
    await git(root, "init", "--bare", "repo.git");
    await git(bare, "symbolic-ref", "HEAD", "refs/heads/main");
    seed = join(root, "seed");
    await git(root, "init", "seed");
    await git(seed, "checkout", "-b", "main");
    writeFileSync(join(seed, "a.txt"), "one\n");
    await git(seed, "add", "a.txt");
    await git(seed, "commit", "-m", "one");
    await git(seed, "tag", "v1");
    await git(seed, "checkout", "-b", "feature");
    writeFileSync(join(seed, "f.txt"), "feature\n");
    await git(seed, "add", "f.txt");
    await git(seed, "commit", "-m", "feature");
    await git(seed, "push", bare, "main", "feature", "v1");

    server = await startGitSmartHttp({
      git: GIT as string,
      projectRoot: root,
      user: USER,
      token: TOKEN,
      env: gitEnv,
    });
    repoUrl = `http://127.0.0.1:${String(server.port)}/repo.git`;
    wt = join(root, "wt");
    await git(root, "clone", bare, "wt");
    await git(wt, "remote", "set-url", "origin", repoUrl);

    // The remote moves after the clone: main advances and v3 marks it, feature2
    // appears with the annotated v2 on it, feature is deleted, and v-orphan names
    // a commit no branch reaches.
    await git(seed, "checkout", "main");
    writeFileSync(join(seed, "a.txt"), "two\n");
    await git(seed, "commit", "-am", "two");
    await git(seed, "tag", "v3");
    await git(seed, "checkout", "-b", "feature2");
    writeFileSync(join(seed, "g.txt"), "feature2\n");
    await git(seed, "add", "g.txt");
    await git(seed, "commit", "-m", "feature2");
    await git(seed, "tag", "-a", "v2", "-m", "annotated");
    await git(seed, "checkout", "--orphan", "lonely");
    await git(seed, "commit", "--allow-empty", "-m", "lonely");
    await git(seed, "tag", "v-orphan");
    await git(seed, "push", bare, "main", "feature2", "v2", "v3", "v-orphan");
    await git(bare, "update-ref", "-d", "refs/heads/feature");

    configBefore = readFileSync(join(wt, ".git", "config"));
    headBefore = readFileSync(join(wt, ".git", "HEAD"), "utf8");
    mainBefore = await refOf(wt, "refs/heads/main");

    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "git-fetch-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(`${USER}:${TOKEN}`, "utf8")),
    });
    handle = created.handle;
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`http://127.0.0.1:${String(server.port)}/*`],
      command_allowlist: [GIT as string],
      env_allowlist: [],
      host_allowlist: [],
    });
    client = new DirectClient(vault.engine);
  });

  afterAll(async () => {
    try {
      if (server !== undefined) await server.close();
      await destroyTestVault(vault);
    } finally {
      if (root !== undefined)
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  // RX-B9-13: an unparsed caller's operation that is not one of the five used to
  // fall into the pull branch and fast-forward the checked-out branch.
  it("refuses an operation that is not one of the five and touches neither the tree nor the remote", async () => {
    const seen = server.requests.length;
    const refsBefore = await refListing(wt);

    await expectVaultError(
      () =>
        client.useSecret(handle, {
          type: "git",
          operation: "bogus",
          repository: repoUrl,
          working_directory: wt,
        } as unknown as UseSecretAction),
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(server.requests.length).toBe(seen);
    expect(await refListing(wt)).toEqual(refsBefore);
    expect(await refOf(wt, "refs/heads/main")).toBe(mainBefore);
    expect(readFileSync(join(wt, "a.txt"), "utf8")).toBe("one\n");
    const rows = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .filter((row) => row.detail?.operation === "bogus");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: false,
      detail: { context: "git", operation: "bogus", error: "INVALID_GIT_CONFIG" },
    });
  });

  it("lands a new remote branch under refs/remotes/origin and moves neither the checked-out branch nor a working file", async () => {
    const seen = server.requests.length;
    const result = await fetchThroughVault();

    expect(result).toMatchObject({ operation: "fetch", exit_code: 0 });
    expect(server.requests.length).toBeGreaterThan(seen);
    expect(await refOf(wt, "refs/remotes/origin/feature2")).toBe(
      await refOf(bare, "refs/heads/feature2"),
    );
    expect(await refOf(wt, "refs/remotes/origin/main")).toBe(await refOf(bare, "refs/heads/main"));
    expect(await refOf(wt, "refs/heads/main")).toBe(mainBefore);
    expect(readFileSync(join(wt, ".git", "HEAD"), "utf8")).toBe(headBefore);
    expect(readFileSync(join(wt, "a.txt"), "utf8")).toBe("one\n");
    expect(await git(wt, "status", "--porcelain")).toBe("");
    // Without --prune the deleted branch's tracking ref stays; the tags git
    // follows on its own arrive, the tag no fetched commit reaches does not.
    const refs = await refNames(wt);
    expect(refs).toEqual(
      expect.arrayContaining(["refs/remotes/origin/feature", "refs/tags/v2", "refs/tags/v3"]),
    );
    expect(refs).not.toContain("refs/tags/v-orphan");
  });

  it("--prune removes the tracking ref of a branch deleted on the remote", async () => {
    expect(await refNames(wt)).toContain("refs/remotes/origin/feature");

    const result = await fetchThroughVault(["--prune"]);

    expect(result).toMatchObject({ operation: "fetch", exit_code: 0 });
    const refs = await refNames(wt);
    expect(refs).not.toContain("refs/remotes/origin/feature");
    expect(refs).toEqual(
      expect.arrayContaining([
        "refs/heads/main",
        "refs/remotes/origin/feature2",
        "refs/remotes/origin/main",
      ]),
    );
    expect(await refOf(wt, "refs/heads/main")).toBe(mainBefore);
  });

  it("--tags brings a tag no fetched branch reaches", async () => {
    expect(await refNames(wt)).not.toContain("refs/tags/v-orphan");

    const result = await fetchThroughVault(["--tags"]);

    expect(result).toMatchObject({ operation: "fetch", exit_code: 0 });
    expect(await refOf(wt, "refs/tags/v-orphan")).toBe(await refOf(bare, "refs/tags/v-orphan"));
    expect(await refOf(wt, "refs/heads/main")).toBe(mainBefore);
  });

  it("leaves the tree's .git/config byte-identical and the credential in no result and no file of the tree", async () => {
    expect(results.map((r) => r.exit_code)).toEqual([0, 0, 0]);
    expect(readFileSync(join(wt, ".git", "config")).equals(configBefore)).toBe(true);
    expect(await refOf(wt, "refs/heads/main")).toBe(mainBefore);
    expect(results).toHaveLength(3);
    const basic = Buffer.from(`${USER}:${TOKEN}`).toString("base64");
    const json = JSON.stringify(results);
    expect(json.includes(TOKEN) || json.includes(basic) || json.includes(USER)).toBe(false);
    for (const file of filesUnder(wt)) {
      const text = readFileSync(file).toString("latin1");
      expect(text.includes(TOKEN) || text.includes(basic) || text.includes(USER), file).toBe(false);
    }
  });

  it("writes one successful secret.use row per fetch, naming the operation", () => {
    const rows = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .filter((row) => row.detail?.operation === "fetch");
    expect(rows).toHaveLength(3);
    for (const row of rows) {
      expect(row).toMatchObject({
        success: true,
        detail: { context: "git", operation: "fetch", transport: "https", exit_code: 0 },
      });
    }
  });
});
