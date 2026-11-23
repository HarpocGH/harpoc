import { execFile } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { GitAction, GitResult } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startGitSmartHttp } from "./helpers/git-smart-http-plain.js";
import type { GitSmartHttp } from "./helpers/git-smart-http-plain.js";
import { assertTierAvailable } from "./helpers/platform-tiers.js";
import { runAs, runCommand } from "./helpers/spawn-cli.js";
import { resolveSupportedGit } from "./helpers/supported-git.js";
import { expectVaultError } from "@harpoc/test-utils";

/**
 * A5 on real git with two accounts: the engine runs in process as the suite's
 * own account, the account the vault runs as; the second account is
 * HARPOC_TWO_UID_AGENT_USER through `sudo -n -u`, root through `sudo -n -u
 * root`. A repository the vault does not serve is refused before git runs in
 * it: the secret's policy passes GIT_TRACE2_EVENT, and after a refusal the
 * trace holds the version read's `start` alone. The rows share the fixture and
 * run in order; the engine is declared a daemon after (d).
 *
 * Linux only, tier `two-uid` (the ubuntu legs and the dev container): where the
 * tier is required, an agent that cannot run git or a root that sudo refuses
 * fails instead of skipping.
 */

const GIT = resolveSupportedGit();
const AGENT_USER = process.env["HARPOC_TWO_UID_AGENT_USER"];
const PASSWORD = "git-owner-master-pw-1";
const USER = "owner_user";
const TOKEN = "owner-token-4d1f7a2b9c";
const GIT_TIMEOUT_MS = 30_000;
const OWNER = "working_directory's repository belongs to another account";
const CHANGEABLE = "working_directory's repository can be changed by another account";

type TreeOperation = "pull" | "push" | "fetch";

interface TraceEvent {
  event: string;
  argv?: string[];
  worktree?: string;
}

describe.skipIf(process.platform !== "linux" || GIT === null)(
  "a repository the vault's account does not hold (Linux only: sudo -n -u and POSIX ownership; skipped where no supported git resolves)",
  () => {
    let available = false;
    let agent = "";
    let agentGid = "";
    let ownUid = "";
    let root = "";
    let bare = "";
    let seed = "";
    let trace = "";
    let server: GitSmartHttp | undefined;
    let repoUrl = "";
    let vault: TestVault | undefined;
    let handle = "";
    let secretId = "";
    let gitEnv: NodeJS.ProcessEnv = {};
    let agentRepository = "";
    let agentDir = "";
    let clone = "";
    let main = "";
    let linkedTree = "";
    let shared = "";
    let underAgent = "";

    const asRoot = (argv: string[]) => runAs("root", argv);

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

    async function cloned(dir: string): Promise<string> {
      await git(root, "clone", "-q", bare, dir);
      await git(dir, "remote", "set-url", "origin", repoUrl);
      return realpathSync(dir);
    }

    /** A `mktemp -d` of the agent's in the system temporary directory, `chmod`ed to `mode`. */
    async function madeByAgent(mode: string): Promise<string> {
      const made = await runAs(agent, [
        "mktemp",
        "-d",
        join(tmpdir(), "harpoc-git-owner-agent-XXXXXX"),
      ]);
      expect(made.code, made.stderr).toBe(0);
      const dir = made.stdout.trim();
      const opened = await runAs(agent, ["chmod", mode, dir]);
      expect(opened.code, opened.stderr).toBe(0);
      return realpathSync(dir);
    }

    async function removedByAgent(dir: string): Promise<void> {
      const removed = await runAs(agent, ["rm", "-rf", "--", dir]);
      expect(removed.code, removed.stderr).toBe(0);
    }

    /** The suite's own directory at `path` in the agent's sticky directory, removed unless the agent put a link there. */
    function removeOwnEntry(path: string): void {
      let isLink: boolean;
      try {
        isLink = lstatSync(path).isSymbolicLink();
      } catch {
        return;
      }
      if (!isLink) rmSync(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }

    function action(wd: string, operation: TreeOperation): GitAction {
      return { type: "git", operation, repository: repoUrl, working_directory: wd };
    }

    function readTrace(): TraceEvent[] {
      if (!existsSync(trace)) return [];
      return readFileSync(trace, "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as TraceEvent);
    }

    /** `run` with GIT_TRACE2_EVENT naming a fresh trace file, unset after; the trace's events. */
    async function traced(run: () => Promise<void>): Promise<TraceEvent[]> {
      rmSync(trace, { force: true });
      process.env.GIT_TRACE2_EVENT = trace;
      try {
        await run();
      } finally {
        delete process.env.GIT_TRACE2_EVENT;
      }
      return readTrace();
    }

    function useRows() {
      return (vault as TestVault).engine.queryAudit({
        secretId,
        eventType: AuditEventType.SECRET_USE,
      });
    }

    async function vaultFetch(wd: string): Promise<{ result: GitResult; events: TraceEvent[] }> {
      let result: GitResult | undefined;
      const events = await traced(async () => {
        const answer = await (vault as TestVault).engine.useSecret(handle, action(wd, "fetch"));
        if (answer.type !== "git") throw new Error("expected a git result");
        result = answer;
      });
      return { result: result as GitResult, events };
    }

    async function refused(
      wd: string,
      message: string,
      operation: TreeOperation = "fetch",
    ): Promise<void> {
      const seen = (server as GitSmartHttp).requests.length;
      const before = new Set(useRows().map((row) => row.id));
      const events = await traced(async () => {
        const err = await expectVaultError(
          () => (vault as TestVault).engine.useSecret(handle, action(wd, operation)),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(message);
      });
      const added = useRows().filter((row) => !before.has(row.id));
      expect(added).toHaveLength(1);
      expect(added[0]?.success).toBe(false);
      expect(added[0]?.detail).toEqual({
        context: "git",
        operation,
        transport: "https",
        error: "INVALID_GIT_CONFIG",
        network_isolation: false,
        fs_isolation: false,
      });
      const written = JSON.stringify(added);
      expect(written.includes(root)).toBe(false);
      expect(written.includes(wd)).toBe(false);
      expect((server as GitSmartHttp).requests.length).toBe(seen);
      expect(
        events.filter((event) => event.event === "start").map((event) => event.argv?.slice(1)),
      ).toEqual([["version"]]);
      expect(events.some((event) => event.event === "def_repo")).toBe(false);
    }

    beforeAll(async () => {
      let probeError: unknown;
      try {
        if (AGENT_USER === undefined) throw new Error("HARPOC_TWO_UID_AGENT_USER is not set");
        const version = await runAs(AGENT_USER, [GIT as string, "version"]);
        if (version.code !== 0) {
          throw new Error(`sudo -n -u ${AGENT_USER} cannot run git: ${version.stderr.trim()}`);
        }
        const rooted = await runAs("root", ["true"]);
        if (rooted.code !== 0) throw new Error(`sudo -n -u root refused: ${rooted.stderr.trim()}`);
        available = true;
      } catch (err) {
        probeError = err;
      }
      assertTierAvailable("two-uid", available, probeError);
      if (!available) return;
      agent = AGENT_USER as string;
      const group = await runAs(agent, ["id", "-g"]);
      expect(group.code, group.stderr).toBe(0);
      agentGid = group.stdout.trim();
      ownUid = String(process.getuid?.());

      root = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-git-owner-")));
      chmodSync(root, 0o755);
      trace = join(root, "trace.json");
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
      delete gitEnv.GIT_TRACE2_EVENT;

      bare = join(root, "repo.git");
      await git(root, "init", "-q", "--bare", "repo.git");
      await git(bare, "symbolic-ref", "HEAD", "refs/heads/main");
      seed = join(root, "seed");
      await git(root, "init", "-q", "seed");
      await git(seed, "checkout", "-q", "-b", "main");
      writeFileSync(join(seed, "a.txt"), "one\n");
      mkdirSync(join(seed, "docs"));
      writeFileSync(join(seed, "docs", "readme.txt"), "docs\n");
      await git(seed, "add", "a.txt", "docs");
      await git(seed, "commit", "-q", "-m", "one");
      await git(seed, "push", "-q", bare, "main");

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
        name: "git-owner-key",
        type: "api_key",
        value: new Uint8Array(Buffer.from(`${USER}:${TOKEN}`, "utf8")),
      });
      handle = created.handle;
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [`http://127.0.0.1:${String(server.port)}/*`],
        command_allowlist: [GIT as string],
        env_allowlist: ["GIT_TRACE2_EVENT"],
        host_allowlist: [],
      });
      secretId = await vault.engine.resolveSecretId(handle);

      agentRepository = await madeByAgent("755");
      const initialised = await runAs(agent, [GIT as string, "init", "-q", agentRepository]);
      expect(initialised.code, initialised.stderr).toBe(0);
      clone = await cloned(join(root, "clone"));
      main = await cloned(join(root, "main"));
      await git(main, "worktree", "add", "-q", "--detach", join(root, "linked"));
      linkedTree = realpathSync(join(root, "linked"));
      shared = await cloned(join(root, "shared"));
      agentDir = await madeByAgent("1777");
      underAgent = await cloned(join(agentDir, "repo"));
    }, 120_000);

    afterAll(async () => {
      try {
        if (available) {
          if (agentDir !== "") {
            removeOwnEntry(join(agentDir, "repo"));
            removeOwnEntry(join(agentDir, "moved"));
            await removedByAgent(agentDir);
          }
          if (agentRepository !== "") await removedByAgent(agentRepository);
        }
        if (server !== undefined) await server.close();
        if (vault !== undefined) await destroyTestVault(vault);
      } finally {
        if (root !== "")
          rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    });

    it("(a) a repository of the second account is refused before git runs: a pull, a push and a fetch", async (ctx) => {
      if (!available) return ctx.skip();
      for (const operation of ["pull", "push", "fetch"] as const) {
        await refused(agentRepository, OWNER, operation);
      }
    }, 60_000);

    it("(b) a repository whose config is the second account's is refused before git runs", async (ctx) => {
      if (!available) return ctx.skip();
      const config = join(clone, ".git", "config");
      try {
        const given = await asRoot(["chown", agent, config]);
        expect(given.code, given.stderr).toBe(0);
        const owner = await runCommand("stat", ["-c", "%U", config]);
        expect(owner.stdout.trim()).toBe(agent);
        await refused(clone, OWNER);
      } finally {
        const back = await asRoot(["chown", ownUid, config]);
        expect(back.code, back.stderr).toBe(0);
      }
    }, 60_000);

    it("(c) a linked work tree whose common directory is the second account's is refused before git runs", async (ctx) => {
      if (!available) return ctx.skip();
      const common = join(main, ".git");
      try {
        const given = await asRoot(["chown", "-R", agent, common]);
        expect(given.code, given.stderr).toBe(0);
        const kept = await asRoot(["chown", "-R", ownUid, join(common, "worktrees")]);
        expect(kept.code, kept.stderr).toBe(0);
        await refused(linkedTree, OWNER);
      } finally {
        const back = await asRoot(["chown", "-R", ownUid, common]);
        expect(back.code, back.stderr).toBe(0);
      }
    }, 60_000);

    it("(d) outside a daemon a repository the agent's group can write, and one under a directory the agent owns, are served", async (ctx) => {
      if (!available) return ctx.skip();
      const regrouped = await asRoot(["chgrp", "-R", agentGid, shared]);
      expect(regrouped.code, regrouped.stderr).toBe(0);
      chmodSync(shared, 0o775);
      chmodSync(join(shared, ".git"), 0o775);
      chmodSync(join(shared, ".git", "config"), 0o664);
      for (const wd of [shared, underAgent]) {
        const { result } = await vaultFetch(wd);
        expect(result.exit_code, result.stderr).toBe(0);
      }
    }, 60_000);

    describe("in a daemon", () => {
      beforeAll(() => {
        if (available) {
          (vault as TestVault).engine.declareDaemon({ protectedDirs: [], protectedFiles: [] });
        }
      });

      it("(e) the second account's repository keeps the owner's message", async (ctx) => {
        if (!available) return ctx.skip();
        await refused(agentRepository, OWNER);
      }, 60_000);

      it("(f) a repository the agent's group can write is refused; the agent can change its configuration", async (ctx) => {
        if (!available) return ctx.skip();
        await refused(shared, CHANGEABLE);
        const changed = await runAs(agent, [
          GIT as string,
          "config",
          "--file",
          join(shared, ".git", "config"),
          "harpoc.probe",
          "1",
        ]);
        expect(changed.code, changed.stderr).toBe(0);
      }, 60_000);

      it("(g) the repository under the agent's directory is refused before the path can be exchanged; the agent can exchange it", async (ctx) => {
        if (!available) return ctx.skip();
        const repo = join(agentDir, "repo");
        const moved = join(agentDir, "moved");
        const elsewhere = join(clone, "docs");
        try {
          await refused(repo, CHANGEABLE);
          const renamed = await runAs(agent, ["mv", "--", repo, moved]);
          expect(renamed.code, renamed.stderr).toBe(0);
          const linked = await runAs(agent, ["ln", "-s", elsewhere, repo]);
          expect(linked.code, linked.stderr).toBe(0);
          expect(readlinkSync(repo)).toBe(elsewhere);
        } finally {
          removeOwnEntry(moved);
          removeOwnEntry(repo);
          await removedByAgent(agentDir);
          agentDir = "";
        }
      }, 60_000);

      it("(h) a repository the account itself made under umask 002 is served", async (ctx) => {
        if (!available) return ctx.skip();
        const previous = process.umask(0o002);
        let made: string;
        try {
          made = await cloned(join(root, "umask-002"));
        } finally {
          process.umask(previous);
        }
        const config = join(made, ".git", "config");
        expect(
          [made, join(made, ".git"), config].map((path) => statSync(path).mode & 0o777),
        ).toEqual([0o775, 0o775, 0o664]);
        expect(statSync(config).gid).toBe(userInfo().gid);

        await git(seed, "checkout", "-q", "-b", "umask-002");
        writeFileSync(join(seed, "b.txt"), "two\n");
        await git(seed, "add", "b.txt");
        await git(seed, "commit", "-q", "-m", "two");
        await git(seed, "push", "-q", bare, "umask-002");

        const { result, events } = await vaultFetch(made);
        expect(result.exit_code, result.stderr).toBe(0);
        expect((await git(made, "rev-parse", "refs/remotes/origin/umask-002")).trim()).toBe(
          (await git(bare, "rev-parse", "refs/heads/umask-002")).trim(),
        );
        expect(events.some((event) => event.event === "def_repo" && event.worktree === made)).toBe(
          true,
        );
      }, 60_000);

      it("(i) a separate git directory under the agent's directory is refused before the path can be exchanged; the agent can exchange it", async (ctx) => {
        if (!available) return ctx.skip();
        const sticky = await madeByAgent("1777");
        const separate = join(sticky, "sep.git");
        const moved = join(sticky, "moved.git");
        const wt = join(root, "wt-separate");
        const elsewhere = join(clone, "docs");
        try {
          await git(root, "init", "-q", "--separate-git-dir", separate, wt);
          await refused(realpathSync(wt), CHANGEABLE);
          const renamed = await runAs(agent, ["mv", "--", separate, moved]);
          expect(renamed.code, renamed.stderr).toBe(0);
          const linked = await runAs(agent, ["ln", "-s", elsewhere, separate]);
          expect(linked.code, linked.stderr).toBe(0);
          expect(readlinkSync(separate)).toBe(elsewhere);
        } finally {
          removeOwnEntry(moved);
          removeOwnEntry(separate);
          await removedByAgent(sticky);
        }
      }, 60_000);
    });
  },
);
