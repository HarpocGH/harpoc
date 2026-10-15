/**
 * The relay repository a pull's or push's credential-bearing step runs against
 * is re-validated by the vault immediately before that step and again after it
 * (S1, C1.2 fix round 1, F-3): every file the vault wrote byte-equal, nothing
 * else at the relay's top level beforehand, and afterwards no file through which
 * git would read configuration from elsewhere. A same-user writer can still win
 * the window between the check and git's read — a recorded limit; these cases
 * pin the check itself. Tampering is deterministic: a pass-through `node:fs`
 * mock edits the relay right after the vault writes its last file (before the
 * check), and the spawn seam edits it while the network step "runs" (after it).
 */
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { expectVaultError } from "@harpoc/test-utils";

const hooks = vi.hoisted(() => ({ afterWrite: null as null | ((path: string) => void) }));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    writeFileSync: (...args: Parameters<typeof actual.writeFileSync>) => {
      actual.writeFileSync(...args);
      if (typeof args[0] === "string") hooks.afterWrite?.(args[0]);
    },
  };
});

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

const GIT = resolveExecutable("git", controlledPathDirs());
// Skipped where git does not resolve: the working-tree probes run real git.
const describeGit = describe.skipIf(GIT === null);

const NULL_GIT_CONFIG = process.platform === "win32" ? "NUL" : "/dev/null";
const REPO = "https://8.8.8.8/org/repo.git";
/** The network steps and the final local hop answer OK; the working-tree probes run real git. */
const MOCKED = ["ls-remote", "fetch", "push", "pull", "clone"];
const PLANTED = "[http]\n\tproxy = http://127.0.0.1:9/\n";

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const { spawnCaptured: realSpawnCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function relayOf(args: string[]): string {
  return (args.find((a) => a.startsWith("--git-dir=")) as string).slice("--git-dir=".length);
}

function policy(): InjectionPolicy {
  return {
    url_allowlist: ["https://8.8.8.8/*"],
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

describeGit(
  "Git relay integrity — the vault re-validates the relay around the network step (S1)",
  () => {
    const injector = new GitInjector(null);
    const spawnMock = vi.mocked(spawnCaptured);
    let scratch: string;
    let wd: string;
    let saved: { TMPDIR?: string; TMP?: string; TEMP?: string };

    beforeEach(() => {
      scratch = mkdtempSync(join(tmpdir(), "harpoc-relay-integrity-"));
      wd = join(scratch, "wd");
      execFileSync(GIT as string, ["init", "-q", wd], {
        env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG },
      });
      saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
      process.env.TMPDIR = scratch;
      process.env.TMP = scratch;
      process.env.TEMP = scratch;
      spawnMock.mockReset();
      spawnMock.mockImplementation((cmd, args, opts) =>
        MOCKED.includes(gitSubcommand(args) ?? "")
          ? Promise.resolve(OK_RESULT)
          : realSpawnCaptured(cmd, args, opts),
      );
    });

    afterEach(() => {
      hooks.afterWrite = null;
      if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = saved.TMPDIR;
      if (saved.TMP === undefined) delete process.env.TMP;
      else process.env.TMP = saved.TMP;
      if (saved.TEMP === undefined) delete process.env.TEMP;
      else process.env.TEMP = saved.TEMP;
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    const relaysLeft = () => readdirSync(scratch).filter((n) => n.startsWith("harpoc-git-relay-"));
    const subcommands = () => spawnMock.mock.calls.map(([, a]) => gitSubcommand(a));
    const run = (operation: GitAction["operation"]) =>
      injector.executeWithSecret(
        { type: "git", operation, repository: REPO, working_directory: wd },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy(),
        undefined,
      );

    /** Runs `tamper` on the relay right after the vault wrote its packed-refs. */
    function tamperAtCreation(tamper: (relay: string) => void): void {
      hooks.afterWrite = (path) => {
        if (
          basename(path) === "packed-refs" &&
          basename(dirname(path)).startsWith("harpoc-git-relay-")
        ) {
          hooks.afterWrite = null;
          tamper(dirname(path));
        }
      };
    }

    /** Runs `tamper` on the relay while the network step of `operation` runs. */
    function tamperDuringNetworkStep(
      operation: "ls-remote" | "fetch" | "push",
      tamper: (relay: string) => void,
    ) {
      spawnMock.mockImplementation((cmd, args, opts) => {
        const sub = gitSubcommand(args);
        if (sub === operation) {
          tamper(relayOf(args));
          return Promise.resolve(OK_RESULT);
        }
        if (MOCKED.includes(sub ?? "")) return Promise.resolve(OK_RESULT);
        return realSpawnCaptured(cmd, args, opts);
      });
    }

    it("a relay config changed before the network step refuses the pull, and no credential-bearing step runs", async () => {
      tamperAtCreation((relay) => appendFileSync(join(relay, "config"), PLANTED));
      await expectVaultError(() => run("pull"), ErrorCode.GIT_OPERATION_FAILED);
      expect(subcommands()).toEqual(["rev-parse", "for-each-ref"]);
      expect(relaysLeft()).toEqual([]);
    });

    it("an entry the vault did not write in the relay refuses the push before its network step", async () => {
      tamperAtCreation((relay) => writeFileSync(join(relay, "commondir"), `${wd}/.git\n`));
      await expectVaultError(() => run("push"), ErrorCode.GIT_OPERATION_FAILED);
      expect(subcommands()).toEqual(["rev-parse", "symbolic-ref", "for-each-ref"]);
      expect(relaysLeft()).toEqual([]);
    });

    it("a relay config changed during the fetch reports the pull failed, and the local pull never runs", async () => {
      tamperDuringNetworkStep("fetch", (relay) => appendFileSync(join(relay, "config"), PLANTED));
      await expectVaultError(() => run("pull"), ErrorCode.GIT_OPERATION_FAILED);
      expect(subcommands()).toEqual(["rev-parse", "for-each-ref", "fetch"]);
      expect(relaysLeft()).toEqual([]);
    });

    it("a commondir planted during the push reports the push failed", async () => {
      tamperDuringNetworkStep("push", (relay) =>
        writeFileSync(join(relay, "commondir"), `${wd}/.git\n`),
      );
      await expectVaultError(() => run("push"), ErrorCode.GIT_OPERATION_FAILED);
      expect(subcommands()).toEqual(["rev-parse", "symbolic-ref", "for-each-ref", "push"]);
      expect(relaysLeft()).toEqual([]);
    });

    const runClone = () =>
      injector.executeWithSecret(
        {
          type: "git",
          operation: "clone",
          repository: REPO,
          working_directory: join(scratch, "dest"),
        },
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        policy(),
        undefined,
      );

    it("a relay config changed before a clone's first network step refuses the clone with no spawn at all (F-1)", async () => {
      tamperAtCreation((relay) => appendFileSync(join(relay, "config"), PLANTED));
      await expectVaultError(runClone, ErrorCode.GIT_OPERATION_FAILED);
      expect(subcommands()).toEqual([]);
      expect(relaysLeft()).toEqual([]);
    });

    it("a relay config changed during the clone's ls-remote refuses the clone before its fetch (F-1)", async () => {
      tamperDuringNetworkStep("ls-remote", (relay) =>
        appendFileSync(join(relay, "config"), PLANTED),
      );
      await expectVaultError(runClone, ErrorCode.GIT_OPERATION_FAILED);
      expect(subcommands()).toEqual(["ls-remote"]);
      expect(relaysLeft()).toEqual([]);
    });

    it("a commondir planted during the clone's fetch reports the clone failed, and the local clone never runs (F-1)", async () => {
      tamperDuringNetworkStep("fetch", (relay) =>
        writeFileSync(join(relay, "commondir"), `${wd}/.git\n`),
      );
      await expectVaultError(runClone, ErrorCode.GIT_OPERATION_FAILED);
      expect(subcommands()).toEqual(["ls-remote", "fetch"]);
      expect(relaysLeft()).toEqual([]);
    });

    it("control: an untouched relay runs the pull through to the local pull", async () => {
      const result = await run("pull");
      expect(result.exit_code).toBe(0);
      expect(subcommands()).toEqual(["rev-parse", "for-each-ref", "fetch", "pull"]);
      expect(relaysLeft()).toEqual([]);
    });

    // POSIX: mkdtemp(3) creates the relay owner-only whatever the umask (characterization —
    // no product line sets the mode). win32 ignores the mode; the directory inherits the
    // ACL of the user's temporary directory, which the same user can write.
    it.skipIf(process.platform === "win32")(
      "the relay directory is owner-only (0700) while the network step runs",
      async () => {
        let mode = -1;
        tamperDuringNetworkStep("fetch", (relay) => {
          mode = statSync(relay).mode & 0o777;
        });
        await run("pull");
        expect(mode).toBe(0o700);
      },
    );
  },
);
