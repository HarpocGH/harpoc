import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { startGitSmartHttp, startRecorder } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { GitInjector } from "./git-injector.js";

/**
 * S5 (code review 2026-10-15), on real git: a clone without working_directory
 * took a bare positional in `args` as the remote and cloned it into a
 * directory named after the validated URL — a second host, or a local
 * repository, the allowlist never saw. Only POSIX reaches it: on win32 the
 * URL-named destination is an invalid path and git fails before connecting.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
// Skipped where git does not resolve, and on win32 (see above).
const describePosixGit = describe.skipIf(GIT === null || process.platform === "win32");

const USER = "vaultuser";
const TOKEN = "S3CRET-TOKEN-xyz";

describePosixGit("Git clone — a positional in args never becomes the remote (S5)", () => {
  const injector = new GitInjector(null);
  let root: string;
  let cwd: string;
  let local: string;
  let server: Listener;
  let recorder: Listener;
  let repoUrl: string;
  let savedCwd: string;

  function policy(): InjectionPolicy {
    return {
      url_allowlist: [`http://127.0.0.1:${String(server.port)}/org/*`],
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

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-git-s5-"));
    const env = {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.com",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.com",
    };
    const srv = join(root, "srv");
    mkdirSync(join(srv, "org"), { recursive: true });
    execFileSync(GIT as string, ["init", "-q", "--bare", join(srv, "org", "repo.git")], { env });
    local = join(root, "localsrc");
    execFileSync(GIT as string, ["init", "-q", local], { env });
    writeFileSync(join(local, "f"), "a local repository\n");
    execFileSync(GIT as string, ["-C", local, "add", "f"], { env });
    execFileSync(GIT as string, ["-C", local, "commit", "-q", "-m", "x"], { env });
    server = await startGitSmartHttp({
      git: GIT as string,
      projectRoot: srv,
      user: USER,
      token: TOKEN,
      env,
    });
    recorder = await startRecorder();
    repoUrl = `http://127.0.0.1:${String(server.port)}/org/repo.git`;
    cwd = join(root, "vault-cwd");
    mkdirSync(cwd);
    savedCwd = process.cwd();
    process.chdir(cwd);
  });

  afterAll(async () => {
    try {
      process.chdir(savedCwd);
      if (server !== undefined) await server.close();
      if (recorder !== undefined) await recorder.close();
    } finally {
      if (root !== undefined)
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it.each([
    ["another host", () => `http://127.0.0.1:${String(recorder.port)}/org/OTHER.git`],
    ["a local repository", () => local],
  ])("without working_directory, %s in args is refused before git runs", async (_label, arg) => {
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "clone", repository: repoUrl, args: [arg()] },
          new Uint8Array(Buffer.from(`${USER}:${TOKEN}`)),
          policy(),
          undefined,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(recorder.requests).toEqual([]);
    expect(readdirSync(cwd)).toEqual([]);
  });

  it("control: with working_directory a positional in args is git's own usage error, and no second host is contacted", async () => {
    const dest = join(root, "dest");
    const before = recorder.requests.length;
    const result = await injector.executeWithSecret(
      {
        type: "git",
        operation: "clone",
        repository: repoUrl,
        args: [`http://127.0.0.1:${String(recorder.port)}/org/OTHER.git`],
        working_directory: dest,
      },
      new Uint8Array(Buffer.from(`${USER}:${TOKEN}`)),
      policy(),
      undefined,
    );
    expect(result.exit_code).not.toBe(0);
    expect(result.stderr).toContain("Too many arguments");
    expect(recorder.requests.slice(before)).toEqual([]);
    expect(existsSync(dest)).toBe(false);
  });
});
