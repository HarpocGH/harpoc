import { execFile } from "node:child_process";
import {
  chmodSync,
  createReadStream,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * N11 (R11, 2026-09-04): a `git pull` into a caller-supplied working tree
 * used to run that tree's own `.git/hooks/post-merge` with the credential in
 * the child environment. The vault now forces `core.hooksPath` to an empty
 * directory it authors. The fixture proves the hook fires under a direct
 * pull (the control), then pulls through the vault and asserts it does not.
 * The bare repository is served over git's dumb HTTP protocol from a Node
 * static file server on 127.0.0.1 — plain `http:` is permitted on loopback.
 *
 * Every git run here is asynchronous by necessity: the static server shares
 * this process's event loop, so a synchronous `execFileSync` git would block
 * the very handler its own transfer needs and deadlock the suite.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
const describeGit = GIT ? describe : describe.skip;
const PASSWORD = "integration-test-pw";
const GIT_TIMEOUT_MS = 30_000;

describeGit("Git context — hooks of the caller's tree never run (N11)", () => {
  let root: string;
  let bare: string;
  let seed: string;
  let wt: string;
  let marker: string;
  let server: Server;
  let repoUrl: string;
  let port: number;
  let vault: TestVault;
  let handle: string;
  let gitEnv: NodeJS.ProcessEnv;
  const savedEnv: Record<string, string | undefined> = {};

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

  function publish(): Promise<string> {
    return git(bare, "update-server-info");
  }

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-hooks-"));
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
    for (const key of ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"]) {
      savedEnv[key] = process.env[key];
      process.env[key] = gitEnv[key];
    }

    bare = join(root, "repo.git");
    await git(root, "init", "--bare", "repo.git");
    await git(bare, "symbolic-ref", "HEAD", "refs/heads/main");

    seed = join(root, "seed");
    await git(root, "init", "seed");
    await git(seed, "checkout", "-b", "main");
    writeFileSync(join(seed, "a.txt"), "one\n");
    await git(seed, "add", "a.txt");
    await git(seed, "commit", "-m", "one");
    await git(seed, "push", bare, "HEAD:refs/heads/main");
    await publish();

    // Dumb-HTTP static server over the bare repository (query strings ignored;
    // no path may escape the repository).
    server = createServer((req, res) => {
      const pathname = (req.url ?? "/").split("?")[0] ?? "/";
      const prefix = "/repo.git/";
      if (!pathname.startsWith(prefix)) {
        res.writeHead(404).end();
        return;
      }
      const file = resolve(bare, decodeURIComponent(pathname.slice(prefix.length)));
      if (!file.startsWith(bare + sep) || !existsSync(file) || !statSync(file).isFile()) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/octet-stream" });
      createReadStream(file).pipe(res);
    });
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    port = (server.address() as AddressInfo).port;
    repoUrl = `http://127.0.0.1:${String(port)}/repo.git`;

    wt = join(root, "wt");
    await git(root, "clone", repoUrl, "wt");
    marker = join(root, "marker");
    const hook = join(wt, ".git", "hooks", "post-merge");
    writeFileSync(hook, `#!/bin/sh\n: > "${marker.replace(/\\/g, "/")}"\n`);
    chmodSync(hook, 0o755);

    writeFileSync(join(seed, "a.txt"), "two\n");
    await git(seed, "commit", "-am", "two");
    await git(seed, "push", bare, "HEAD:refs/heads/main");
    await publish();

    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "git-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("user:hooks-test-token", "utf8")),
    });
    handle = created.handle;
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`http://127.0.0.1:${String(port)}/*`],
      command_allowlist: [GIT as string],
      env_allowlist: ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"],
      host_allowlist: [],
    });
  });

  afterAll(async () => {
    try {
      if (server !== undefined) await new Promise<void>((done) => server.close(() => done()));
      await destroyTestVault(vault).catch(() => {});
    } finally {
      for (const [key, value] of Object.entries(savedEnv)) {
        if (value === undefined) Reflect.deleteProperty(process.env, key);
        else process.env[key] = value;
      }
      if (root !== undefined) rmSync(root, { recursive: true, force: true });
    }
  });

  it("control: a direct pull runs the tree's post-merge hook", async () => {
    await git(wt, "pull", "--ff-only", repoUrl, "main");
    expect(existsSync(marker)).toBe(true);
    expect(readFileSync(join(wt, "a.txt"), "utf8")).toBe("two\n");
    rmSync(marker);
    await git(wt, "reset", "--hard", "HEAD~1");
    expect(readFileSync(join(wt, "a.txt"), "utf8")).toBe("one\n");
  });

  it("a pull through the vault fast-forwards the tree and never runs the hook", async () => {
    const client = new DirectClient(vault.engine);
    const result = await client.useSecret(handle, {
      type: "git",
      operation: "pull",
      repository: repoUrl,
      working_directory: wt,
      args: ["--ff-only"],
    });
    expect(result).toMatchObject({ exit_code: 0 });
    expect(readFileSync(join(wt, "a.txt"), "utf8")).toBe("two\n");
    expect(existsSync(marker)).toBe(false);
  });
});
