import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import type { GitResult } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startGitSmartHttp } from "./helpers/git-smart-http-plain.js";
import type { GitSmartHttp } from "./helpers/git-smart-http-plain.js";
import { tierRequired } from "./helpers/platform-tiers.js";

/**
 * M6 (deployment model B, tranche B9): `ls-remote` through the vault on a real
 * engine with the real git, against a smart-HTTP remote on 127.0.0.1 that
 * answers only the Basic credential the secret holds. The one
 * credential-bearing step runs against a vault-written relay, with no working
 * tree; its stdout — refnames and object ids the remote chose — comes back
 * through the same exact-value redaction as every git result, and so does a
 * `remote:` line in which a hostile remote reflects the credential.
 *
 * Every git run here is asynchronous: the smart-HTTP fixture shares this
 * process's event loop, so a synchronous git would block its own transfer.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
const describeGit = describe.skipIf(GIT === null);
const PASSWORD = "integration-test-pw";
const GIT_TIMEOUT_MS = 30_000;
const USER = "ls-user";
const TOKEN = "ls-remote-token-2d4f6b8a";
const BASIC = Buffer.from(`${USER}:${TOKEN}`).toString("base64");

// A leg that exports the ssh-live tier ships git as well (TM-11): where git does not resolve
// on such a leg, this guard fails the file instead of letting the suite below skip silently.
it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

describeGit("Git context — ls-remote through the vault (M6)", () => {
  let root: string;
  let bare: string;
  let server: GitSmartHttp;
  let repoUrl: string;
  let vault: TestVault;
  let handle: string;
  let client: DirectClient;
  let gitEnv: NodeJS.ProcessEnv;

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

  function gitOnLeakRef(...args: string[]): Promise<void> {
    return new Promise((done, fail) => {
      execFile(GIT as string, args, { cwd: bare, env: gitEnv, timeout: GIT_TIMEOUT_MS }, (err) => {
        if (err) fail(new Error("git on the credential-named ref failed"));
        else done();
      });
    });
  }

  const refOf = async (ref: string): Promise<string> => (await git(bare, "rev-parse", ref)).trim();

  async function lsRemote(args?: string[]): Promise<GitResult> {
    const result = await client.useSecret(handle, {
      type: "git",
      operation: "ls-remote",
      repository: repoUrl,
      ...(args === undefined ? {} : { args }),
    });
    if (result.type !== "git") throw new Error("expected a git result");
    return result;
  }

  const lastRow = () =>
    vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .filter((row) => row.detail?.operation === "ls-remote")[0];

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-ls-remote-"));
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
    const seed = join(root, "seed");
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
    await git(seed, "tag", "-a", "v2", "-m", "annotated");
    await git(seed, "push", bare, "main", "feature", "v1", "v2");

    server = await startGitSmartHttp({
      git: GIT as string,
      projectRoot: root,
      user: USER,
      token: TOKEN,
      env: gitEnv,
    });
    repoUrl = `http://127.0.0.1:${String(server.port)}/repo.git`;

    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "git-ls-remote-key",
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

  it("lists the remote's refs on stdout, --symref's ref: line first, with no working tree", async () => {
    const seen = server.requests.length;
    const result = await lsRemote(["--symref"]);

    expect(result).toMatchObject({ operation: "ls-remote", exit_code: 0 });
    expect(server.requests.length).toBeGreaterThan(seen);
    const main = await refOf("refs/heads/main");
    const feature = await refOf("refs/heads/feature");
    const lines = result.stdout.split(/\r?\n/);
    expect(lines[0]).toBe("ref: refs/heads/main\tHEAD");
    expect(lines).toEqual(
      expect.arrayContaining([
        `${main}\tHEAD`,
        `${main}\trefs/heads/main`,
        `${feature}\trefs/heads/feature`,
        `${await refOf("refs/tags/v1")}\trefs/tags/v1`,
        `${await refOf("refs/tags/v2")}\trefs/tags/v2`,
        `${feature}\trefs/tags/v2^{}`,
      ]),
    );
    expect(lastRow()).toMatchObject({
      success: true,
      detail: { context: "git", operation: "ls-remote", transport: "https", exit_code: 0 },
    });
  });

  it("redacts a credential the remote names in a ref", async () => {
    await gitOnLeakRef("update-ref", `refs/heads/leak-${TOKEN}`, "refs/heads/main");
    try {
      const result = await lsRemote();

      expect(result.operation).toBe("ls-remote");
      expect(result.exit_code).toBe(0);
      expect(result.stdout.includes("\trefs/heads/leak-[REDACTED]")).toBe(true);
      const json = JSON.stringify(result);
      expect(json.includes(TOKEN) || json.includes(BASIC) || json.includes(USER)).toBe(false);
      expect(lastRow()).toMatchObject({
        success: true,
        detail: { operation: "ls-remote", exit_code: 0, sanitized: true },
      });
    } finally {
      await gitOnLeakRef("update-ref", "-d", `refs/heads/leak-${TOKEN}`);
    }
  });

  it("redacts a credential a hostile remote reflects in its error body", async () => {
    server.reflect(true);
    try {
      const result = await lsRemote();

      expect(result.operation).toBe("ls-remote");
      expect(result.exit_code).toBe(128);
      expect(result.stderr.includes("remote: denied for [REDACTED]:[REDACTED]")).toBe(true);
      const json = JSON.stringify(result);
      expect(json.includes(TOKEN) || json.includes(BASIC) || json.includes(USER)).toBe(false);
      expect(lastRow()).toMatchObject({
        success: true,
        detail: { operation: "ls-remote", exit_code: 128, sanitized: true },
      });
    } finally {
      server.reflect(false);
    }
  });

  it("carries the credential in no secret.use row", () => {
    const rows = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(rows.filter((row) => row.detail?.operation === "ls-remote")).toHaveLength(3);
    const text = JSON.stringify(rows);
    expect(text.includes(TOKEN) || text.includes(BASIC) || text.includes(USER)).toBe(false);
  });
});
