import { execFile, spawn } from "node:child_process";
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
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { tierRequired } from "./helpers/platform-tiers.js";

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
 *
 * S1 (code review 2026-10-15): the vault's git reads no system config. The
 * policies allowlist GIT_CONFIG_SYSTEM, pointed at a scratch file whose
 * credential helper logs every call, so the suite never reaches the host's
 * own system config (Git for Windows names its credential manager there) and
 * each use asserts the logging helper never ran.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
const describeGit = describe.skipIf(GIT === null);
const PASSWORD = "integration-test-pw";
const GIT_TIMEOUT_MS = 30_000;

// A leg that exports the ssh-live tier ships git as well (TM-11): where git does not resolve
// on such a leg, this guard fails the file instead of letting the suite below skip silently.
it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

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
  let helperLog: string;
  let savedSystem: string | undefined;

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
    helperLog = join(root, "system-helper.log");
    const helper = join(root, "system-helper.sh");
    writeFileSync(
      helper,
      `#!/bin/sh\necho "$1" >> "${helperLog.replace(/\\/g, "/")}"\ncat > /dev/null\n`,
    );
    chmodSync(helper, 0o755);
    const systemConfig = join(root, "system.gitconfig");
    writeFileSync(systemConfig, `[credential]\n\thelper = !${helper.replace(/\\/g, "/")}\n`);
    savedSystem = process.env.GIT_CONFIG_SYSTEM;
    process.env.GIT_CONFIG_SYSTEM = systemConfig;

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
      env_allowlist: ["GIT_CONFIG_SYSTEM"],
      host_allowlist: [],
    });
  });

  afterAll(async () => {
    try {
      if (server !== undefined) await new Promise<void>((done) => server.close(() => done()));
      await destroyTestVault(vault);
    } finally {
      if (savedSystem === undefined) Reflect.deleteProperty(process.env, "GIT_CONFIG_SYSTEM");
      else process.env.GIT_CONFIG_SYSTEM = savedSystem;
      if (root !== undefined)
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
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
    expect(existsSync(helperLog)).toBe(false);
  });

  // I18 (test-review-2026-10-09): a push through the vault. Dumb HTTP cannot
  // take a push, so the same bare repository is served again over git's smart
  // HTTP protocol — `git http-backend` as a CGI behind a second listener on
  // 127.0.0.1 — which admits git-receive-pack only with the Basic credential
  // the push secret holds (http-backend enables receive-pack once REMOTE_USER
  // is set): the push succeeds only if the vault-authored askpass helper
  // hands git the credential.
  describe("a push through the vault (I18)", () => {
    const PUSH_USER = "git-pusher";
    const PUSH_TOKEN = "push-test-token-5e4d3c2b";
    let smart: Server;
    let smartUrl: string;
    let pushHandle: string;
    let authorizedPushes = 0;

    function httpBackend(req: IncomingMessage, res: ServerResponse): void {
      const [pathname = "/", query = ""] = (req.url ?? "/").split("?");
      const receivePack =
        pathname.endsWith("/git-receive-pack") || query === "service=git-receive-pack";
      const basic = `Basic ${Buffer.from(`${PUSH_USER}:${PUSH_TOKEN}`).toString("base64")}`;
      const authorized = req.headers.authorization === basic;
      if (receivePack && !authorized) {
        res.writeHead(401, { "www-authenticate": 'Basic realm="harpoc-test"' }).end();
        return;
      }
      let pathInfo: string;
      try {
        pathInfo = decodeURIComponent(pathname);
      } catch {
        res.writeHead(400).end();
        return;
      }
      if (receivePack) authorizedPushes++;
      const fail = (): void => {
        if (!res.headersSent) res.writeHead(502);
        res.end();
      };
      const cgi = spawn(GIT as string, ["http-backend"], {
        timeout: GIT_TIMEOUT_MS,
        env: {
          ...gitEnv,
          GIT_PROJECT_ROOT: root,
          GIT_HTTP_EXPORT_ALL: "1",
          PATH_INFO: pathInfo,
          QUERY_STRING: query,
          REQUEST_METHOD: req.method ?? "GET",
          CONTENT_TYPE: req.headers["content-type"] ?? "",
          REMOTE_ADDR: "127.0.0.1",
          ...(req.headers["content-length"] === undefined
            ? {}
            : { CONTENT_LENGTH: req.headers["content-length"] }),
          ...(req.headers["content-encoding"] === undefined
            ? {}
            : { HTTP_CONTENT_ENCODING: req.headers["content-encoding"] }),
          ...(authorized ? { REMOTE_USER: PUSH_USER } : {}),
        },
      });
      cgi.on("error", fail);
      cgi.stdin.on("error", fail);
      req.pipe(cgi.stdin);
      const out: Buffer[] = [];
      cgi.stdout.on("data", (chunk: Buffer) => out.push(chunk));
      cgi.on("close", () => {
        if (res.headersSent) return;
        const raw = Buffer.concat(out);
        const end = raw.indexOf("\r\n\r\n");
        if (end < 0) {
          fail();
          return;
        }
        let status = 200;
        const headers: Record<string, string> = {};
        for (const line of raw.subarray(0, end).toString("latin1").split("\r\n")) {
          const colon = line.indexOf(":");
          const name = line.slice(0, colon).trim().toLowerCase();
          const value = line.slice(colon + 1).trim();
          if (name === "status") status = Number.parseInt(value, 10);
          else headers[name] = value;
        }
        res.writeHead(status, headers).end(raw.subarray(end + 4));
      });
    }

    beforeAll(async () => {
      smart = createServer(httpBackend);
      await new Promise<void>((done, fail) => {
        smart.once("error", fail);
        smart.listen(0, "127.0.0.1", done);
      });
      const smartPort = (smart.address() as AddressInfo).port;
      smartUrl = `http://127.0.0.1:${String(smartPort)}/repo.git`;

      const created = await vault.engine.createSecret({
        name: "git-push-key",
        type: "api_key",
        value: new Uint8Array(Buffer.from(`${PUSH_USER}:${PUSH_TOKEN}`, "utf8")),
      });
      pushHandle = created.handle;
      await vault.engine.setInjectionPolicy(pushHandle, {
        url_allowlist: [`http://127.0.0.1:${String(smartPort)}/*`],
        command_allowlist: [GIT as string],
        env_allowlist: ["GIT_CONFIG_SYSTEM"],
        host_allowlist: [],
      });
    });

    afterAll(async () => {
      if (smart !== undefined) await new Promise<void>((done) => smart.close(() => done()));
    });

    it("moves the remote ref and never runs the tree's pre-push hook", async () => {
      const client = new DirectClient(vault.engine);
      const clone = join(root, "push-wt");
      const cloned = await client.useSecret(pushHandle, {
        type: "git",
        operation: "clone",
        repository: smartUrl,
        working_directory: clone,
      });
      expect(cloned).toMatchObject({ exit_code: 0 });
      const prePushMarker = join(root, "pre-push-marker");
      const hook = join(clone, ".git", "hooks", "pre-push");
      writeFileSync(hook, `#!/bin/sh\n: > "${prePushMarker.replace(/\\/g, "/")}"\n`);
      chmodSync(hook, 0o755);
      writeFileSync(join(clone, "b.txt"), "pushed\n");
      await git(clone, "add", "b.txt");
      await git(clone, "commit", "-m", "pushed through the vault");
      const head = (await git(clone, "rev-parse", "HEAD")).trim();
      expect((await git(bare, "rev-parse", "refs/heads/main")).trim()).not.toBe(head);

      const pushed = await client.useSecret(pushHandle, {
        type: "git",
        operation: "push",
        repository: smartUrl,
        working_directory: clone,
      });

      expect(pushed).toMatchObject({ exit_code: 0 });
      expect(existsSync(helperLog)).toBe(false);
      expect((await git(bare, "rev-parse", "refs/heads/main")).trim()).toBe(head);
      expect(authorizedPushes).toBeGreaterThan(0);
      expect(existsSync(prePushMarker)).toBe(false);
      expect(JSON.stringify(pushed)).not.toContain(PUSH_TOKEN);
      const pushRows = vault.engine
        .queryAudit({ eventType: AuditEventType.SECRET_USE })
        .filter((event) => event.detail?.operation === "push");
      expect(pushRows).toHaveLength(1);
      expect(pushRows[0]).toMatchObject({
        success: true,
        detail: { context: "git", operation: "push", transport: "https", exit_code: 0 },
      });
    });
  });
});
