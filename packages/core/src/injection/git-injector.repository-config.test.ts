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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { GitAction, InjectionPolicy } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { startGitSmartHttp, startRecorder } from "./__fixtures__/git-smart-http.js";
import type { Listener } from "./__fixtures__/git-smart-http.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { GitInjector } from "./git-injector.js";

/**
 * S1 (code review 2026-10-15): the caller's repository config — and the host's
 * system and global config — never sees the credential. Real git against a
 * smart-HTTP listener on 127.0.0.1 that answers every request 401 without the
 * Basic credential, so each pull and push here succeeds only when the
 * vault's askpass helper supplied it. The marker scripts record their
 * environment and stdin; a marker holding the token is a leak.
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

describeGit(
  "Git context — repository, system and global config never see the credential (S1)",
  () => {
    const injector = new GitInjector(null);
    let root: string;
    let marks: string;
    let bin: string;
    let bare: string;
    let seed: string;
    let wt: string;
    let vaultTemp: string;
    let server: Listener;
    let recorder: Listener;
    let repoUrl: string;
    let gitEnv: NodeJS.ProcessEnv;
    const savedEnv: Record<string, string | undefined> = {};
    const ENV_NAMES = [
      "GIT_CONFIG_SYSTEM",
      "GIT_CONFIG_NOSYSTEM",
      "GIT_CONFIG_GLOBAL",
      "HOME",
      "USERPROFILE",
      "TMPDIR",
      "TMP",
      "TEMP",
    ];

    const fwd = (p: string) => p.replace(/\\/g, "/");

    function git(cwd: string, ...args: string[]): string {
      return execFileSync(GIT as string, args, { cwd, env: gitEnv, encoding: "utf8" });
    }

    function marker(name: string, mode: "env" | "stdin" | "passthrough"): string {
      const script = join(bin, `${name}.sh`);
      const tail =
        mode === "stdin"
          ? `cat > "${fwd(marks)}/${name}.$$.stdin"\n`
          : mode === "passthrough"
            ? "cat\n"
            : "";
      writeFileSync(script, `#!/bin/sh\nenv > "${fwd(marks)}/${name}.$$.env"\n${tail}exit 0\n`);
      chmodSync(script, 0o755);
      return fwd(script);
    }

    function ran(): string[] {
      return [...new Set(readdirSync(marks).map((f) => f.split(".")[0] as string))].sort();
    }

    function leaked(): string[] {
      return readdirSync(marks)
        .filter((f) => readFileSync(join(marks, f), "utf8").includes(TOKEN))
        .sort();
    }

    function sawToken(listener: Listener): boolean {
      return listener.requests.some((r) => {
        const value = r.authorization?.replace(/^Basic /, "") ?? "";
        return Buffer.from(value, "base64").toString("utf8").includes(TOKEN);
      });
    }

    function addConfig(lines: string): void {
      const config = join(wt, ".git", "config");
      writeFileSync(config, readFileSync(config, "utf8") + lines);
    }

    function policy(envAllowlist: string[] = ["GIT_CONFIG_SYSTEM"]): InjectionPolicy {
      return {
        url_allowlist: [`http://127.0.0.1:${String(server.port)}/*`],
        command_allowlist: [GIT as string],
        env_allowlist: envAllowlist,
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

    async function use(action: Omit<GitAction, "type" | "repository">, envAllowlist?: string[]) {
      return injector.executeWithSecret(
        { type: "git", repository: repoUrl, ...action },
        SECRET,
        policy(envAllowlist),
        undefined,
      );
    }

    beforeAll(async () => {
      root = mkdtempSync(join(tmpdir(), "harpoc-git-repocfg-"));
      for (const key of ENV_NAMES) savedEnv[key] = process.env[key];
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
      bin = join(root, "bin");
      mkdirSync(bin);
      marks = join(root, "marks");
      mkdirSync(marks);
      const srv = join(root, "srv");
      mkdirSync(srv);
      bare = join(srv, "repo.git");
      git(srv, "init", "-q", "--bare", "repo.git");
      git(bare, "symbolic-ref", "HEAD", "refs/heads/main");
      seed = join(root, "seed");
      git(root, "init", "-q", "seed");
      git(seed, "checkout", "-q", "-b", "main");
      writeFileSync(join(seed, ".gitattributes"), "*.evil filter=evil merge=evil\n");
      writeFileSync(join(seed, "a.txt"), "one\n");
      writeFileSync(join(seed, "m.evil"), "base\n");
      git(seed, "add", ".");
      git(seed, "commit", "-q", "-m", "one");
      git(seed, "push", "-q", bare, "HEAD:refs/heads/main");

      server = await startGitSmartHttp({
        git: GIT as string,
        projectRoot: srv,
        user: USER,
        token: TOKEN,
        env: gitEnv,
      });
      recorder = await startRecorder();
      repoUrl = `http://127.0.0.1:${String(server.port)}/repo.git`;

      const system = join(root, "system.gitconfig");
      writeFileSync(
        system,
        `[credential]\n\thelper = !${marker("syshelper", "stdin")}\n[http]\n\tproxy = http://127.0.0.1:${String(recorder.port)}\n`,
      );
      process.env.GIT_CONFIG_SYSTEM = system;
    });

    beforeEach(() => {
      for (const f of readdirSync(marks)) rmSync(join(marks, f));
      vaultTemp = mkdtempSync(join(root, "vault-tmp-"));
      process.env.TMPDIR = vaultTemp;
      process.env.TMP = vaultTemp;
      process.env.TEMP = vaultTemp;
      wt = join(root, `wt-${String(Date.now())}-${String(Math.random()).slice(2, 8)}`);
      git(root, "clone", "-q", bare, wt);
      git(wt, "checkout", "-q", "main");
      git(wt, "config", "user.name", "harpoc-test");
      git(wt, "config", "user.email", "test@example.com");
      writeFileSync(join(seed, "a.txt"), `two ${wt}\n`);
      writeFileSync(join(seed, "b.evil"), "checked out through the filter\n");
      writeFileSync(join(seed, "m.evil"), "upstream\n");
      git(seed, "add", ".");
      git(seed, "commit", "-q", "-m", "two");
      git(seed, "push", "-q", "-f", bare, "HEAD:refs/heads/main");
    });

    afterEach(() => {
      for (const key of ["TMPDIR", "TMP", "TEMP"]) {
        const value = savedEnv[key];
        if (value === undefined) Reflect.deleteProperty(process.env, key);
        else process.env[key] = value;
      }
      expect(readdirSync(vaultTemp)).toEqual([]);
    });

    afterAll(async () => {
      try {
        if (server !== undefined) await server.close();
        if (recorder !== undefined) await recorder.close();
      } finally {
        for (const [key, value] of Object.entries(savedEnv)) {
          if (value === undefined) Reflect.deleteProperty(process.env, key);
          else process.env[key] = value;
        }
        if (root !== undefined)
          rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    });

    describe("pull (face b)", () => {
      it("no credential helper and no fsmonitor of the tree runs; its smudge filter and merge driver run without the credential", async () => {
        writeFileSync(join(wt, "m.evil"), "local\n");
        git(wt, "commit", "-q", "-am", "local");
        const included = join(root, `included-${String(Date.now())}.gitconfig`);
        writeFileSync(included, `[credential]\n\thelper = !${marker("inchelper", "stdin")}\n`);
        addConfig(
          [
            "[core]",
            `\tfsmonitor = ${marker("fsmonitor", "env")}`,
            "[credential]",
            `\thelper = !${marker("treehelper", "stdin")}`,
            "[include]",
            `\tpath = ${fwd(included)}`,
            '[filter "evil"]',
            `\tsmudge = ${marker("smudge", "passthrough")}`,
            "\tclean = cat",
            '[merge "evil"]',
            `\tdriver = ${marker("mergedriver", "env")} %O %A %B`,
            "",
          ].join("\n"),
        );

        const result = await use({
          operation: "pull",
          working_directory: wt,
          args: ["--no-rebase"],
        });

        expect(result.exit_code, result.stderr).toBe(0);
        expect(readFileSync(join(wt, "b.evil"), "utf8")).toBe("checked out through the filter\n");
        expect(leaked()).toEqual([]);
        expect(ran()).toEqual(["mergedriver", "smudge"]);
        expect(JSON.stringify(result)).not.toContain(TOKEN);
      });

      it("the tree's http.proxy and http.extraHeader never reach the authenticated fetch", async () => {
        addConfig(
          [
            "[http]",
            `\tproxy = http://127.0.0.1:${String(recorder.port)}`,
            "\textraHeader = X-Harpoc-Evil: from-the-tree",
            "",
          ].join("\n"),
        );
        const before = server.requests.length;

        const result = await use({ operation: "pull", working_directory: wt, args: ["--ff-only"] });

        expect(sawToken(recorder)).toBe(false);
        expect(result.exit_code, result.stderr).toBe(0);
        expect(readFileSync(join(wt, "a.txt"), "utf8")).toBe(`two ${wt}\n`);
        expect(recorder.requests).toEqual([]);
        const seen = server.requests.slice(before);
        expect(seen.length).toBeGreaterThan(0);
        expect(seen.every((r) => r.headers["x-harpoc-evil"] === undefined)).toBe(true);
        expect(leaked()).toEqual([]);
      });

      it("the tree's url.insteadOf cannot move the credential to another port", async () => {
        addConfig(
          [
            `[url "http://127.0.0.1:${String(recorder.port)}/"]`,
            `\tinsteadOf = http://127.0.0.1:${String(server.port)}/`,
            "",
          ].join("\n"),
        );

        const result = await use({ operation: "pull", working_directory: wt, args: ["--ff-only"] });

        expect(sawToken(recorder)).toBe(false);
        expect(result.exit_code, result.stderr).toBe(0);
        expect(readFileSync(join(wt, "a.txt"), "utf8")).toBe(`two ${wt}\n`);
      });
    });

    describe("push (face b)", () => {
      it("no credential helper or fsmonitor of the tree runs, and its http.proxy and extraHeader never see the push", async () => {
        git(wt, "pull", "-q", "--ff-only", bare, "main");
        writeFileSync(join(wt, "c.txt"), "pushed\n");
        git(wt, "add", "c.txt");
        git(wt, "commit", "-q", "-m", "pushed through the vault");
        const head = git(wt, "rev-parse", "HEAD").trim();
        addConfig(
          [
            "[core]",
            `\tfsmonitor = ${marker("fsmonitor", "env")}`,
            "[credential]",
            `\thelper = !${marker("treehelper", "stdin")}`,
            "[http]",
            `\tproxy = http://127.0.0.1:${String(recorder.port)}`,
            "\textraHeader = X-Harpoc-Evil: from-the-tree",
            "",
          ].join("\n"),
        );
        const before = server.requests.length;

        const result = await use({ operation: "push", working_directory: wt });

        expect(sawToken(recorder)).toBe(false);
        expect(result.exit_code, result.stderr).toBe(0);
        expect(git(bare, "rev-parse", "refs/heads/main").trim()).toBe(head);
        expect(recorder.requests).toEqual([]);
        expect(
          server.requests.slice(before).every((r) => r.headers["x-harpoc-evil"] === undefined),
        ).toBe(true);
        expect(leaked()).toEqual([]);
        expect(ran()).toEqual([]);
      });
    });

    describe("push through the relay's after-check (C1 final fix X1)", () => {
      it("a plain push passes the after-check end to end; -u is refused before any spawn and the remote does not move", async () => {
        git(wt, "fetch", "-q", bare, "main");
        git(wt, "reset", "-q", "--hard", "FETCH_HEAD");
        writeFileSync(join(wt, "d.txt"), "plain push\n");
        git(wt, "add", "d.txt");
        git(wt, "commit", "-q", "-m", "plain push through the vault");
        const head = git(wt, "rev-parse", "HEAD").trim();
        const before = git(bare, "rev-parse", "refs/heads/main").trim();

        let thrown: unknown;
        try {
          await use({ operation: "push", working_directory: wt, args: ["-u"] });
        } catch (err) {
          thrown = err;
        }
        const after = git(bare, "rev-parse", "refs/heads/main").trim();
        // Before the refusal, git recorded the upstream in the relay's config, the
        // after-check reported GIT_OPERATION_FAILED, and the remote had moved.
        expect({
          code: (thrown as { code?: string } | undefined)?.code,
          remote: after === before ? "unmoved" : "moved",
        }).toEqual({ code: "INVALID_GIT_CONFIG", remote: "unmoved" });

        const result = await use({ operation: "push", working_directory: wt });
        expect(result.exit_code, result.stderr).toBe(0);
        expect(git(bare, "rev-parse", "refs/heads/main").trim()).toBe(head);
      });
    });

    describe("the credential-free local pull speaks no transport but file (C1 final fix X2)", () => {
      it("a submodule fetch the tree's config asks of the local pull is refused, and its other host sees nothing", async () => {
        const subsrc = join(root, `subsrc-${String(Date.now())}`);
        git(root, "init", "-q", "-b", "main", subsrc);
        writeFileSync(join(subsrc, "s.txt"), "sub\n");
        git(subsrc, "add", "s.txt");
        git(subsrc, "commit", "-q", "-m", "sub");
        git(wt, "-c", "protocol.file.allow=always", "submodule", "add", "-q", subsrc, "sub");
        git(wt, "commit", "-q", "-m", "add sub");
        const elsewhere = `http://127.0.0.1:${String(recorder.port)}/sub.git`;
        git(wt, "config", "submodule.sub.url", elsewhere);
        git(join(wt, "sub"), "config", "remote.origin.url", elsewhere);
        git(wt, "config", "fetch.recurseSubmodules", "true");
        const before = recorder.requests.length;

        const result = await use({
          operation: "pull",
          working_directory: wt,
          args: ["--no-rebase"],
        });

        expect(recorder.requests.slice(before)).toEqual([]);
        expect(result.stderr).toMatch(/transport 'http' not allowed/);
        expect(leaked()).toEqual([]);
      });
    });

    describe("system and global config (face a)", () => {
      it("neither the system config nor a HOME .gitconfig — helper or proxy — is read, even with every name allowlisted", async () => {
        const home = mkdtempSync(join(root, "home-"));
        writeFileSync(
          join(home, ".gitconfig"),
          `[credential]\n\thelper = !${marker("globalhelper", "stdin")}\n[http]\n\tproxy = http://127.0.0.1:${String(recorder.port)}\n`,
        );
        const before = recorder.requests.length;
        process.env.HOME = home;
        process.env.USERPROFILE = home;
        process.env.GIT_CONFIG_NOSYSTEM = "0";
        process.env.GIT_CONFIG_GLOBAL = join(home, ".gitconfig");
        const dest = join(root, `clone-${String(Date.now())}`);
        try {
          const result = await use(
            { operation: "clone", working_directory: dest },
            ENV_NAMES.slice(0, 5),
          );
          expect(recorder.requests.slice(before)).toEqual([]);
          expect(result.exit_code, result.stderr).toBe(0);
          expect(existsSync(join(dest, "a.txt"))).toBe(true);
          expect(ran()).toEqual([]);
          expect(leaked()).toEqual([]);
        } finally {
          for (const key of ["HOME", "USERPROFILE", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"]) {
            const value = savedEnv[key];
            if (value === undefined) Reflect.deleteProperty(process.env, key);
            else process.env[key] = value;
          }
        }
      });
    });
  },
);
