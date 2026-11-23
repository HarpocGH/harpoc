import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import type { Stats } from "node:fs";
import { lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { resolveSupportedGit } from "./__fixtures__/supported-git.js";
import type { readGitVersion } from "./git-injector-version.js";
import { GitInjector } from "./git-injector.js";
import type { DaemonPaths } from "./local-path.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { expectVaultError } from "@harpoc/test-utils";

const readVersion = vi.hoisted(() => vi.fn<typeof readGitVersion>());

vi.mock("./git-injector-version.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./git-injector-version.js")>();
  return { ...actual, readGitVersion: readVersion };
});
vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, lstat: vi.fn(actual.lstat) };
});

const actualFs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");

const GIT = resolveSupportedGit();
const SSH = resolveNativeSshClient("ssh");
const WIN32 = process.platform === "win32";

const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
const SSH_HOST = "allowed.invalid";
const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;
const KNOWN_HOSTS: ConnectionConfig = {
  ssh: { known_hosts: [`${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`] },
};
const PINNED_CA: ConnectionConfig = { git: { ca_pem: "unused-ca-pem" } };
const SCRIPTED_SECRET = new Uint8Array(Buffer.from("git-user:owner-token-value"));
const OWNER = "working_directory's repository belongs to another account";
const CHANGEABLE = "working_directory's repository can be changed by another account";
const NO_PATHS: DaemonPaths = { protectedDirs: [], protectedFiles: [] };

const TREE_OPERATIONS = ["pull", "push", "fetch"] as const;
type TreeOperation = (typeof TREE_OPERATIONS)[number];
type Floor = Parameters<GitInjector["executeWithSecret"]>[6];
type SpawnCall = Parameters<typeof spawnCaptured>;

const OK_STEP: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function policy(): InjectionPolicy {
  return {
    url_allowlist: ["https://8.8.8.8/*"],
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: [SSH_HOST],
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

const spawnMock = vi.mocked(spawnCaptured);
const foreignPaths = new Set<string>();
let root: string;
let vaultDir: string;
let log: Mock;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-git-owner-injector-")));
  vaultDir = join(root, "vault");
  mkdirSync(vaultDir);
  writeFileSync(join(vaultDir, "vault.db"), "");
  writeFileSync(join(vaultDir, "session.json"), "");
  const gitDir = join(root, "tree", ".git");
  mkdirSync(join(gitDir, "objects"), { recursive: true });
  mkdirSync(join(gitDir, "refs"));
  writeFileSync(join(gitDir, "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(gitDir, "config"), "");
  chmodSync(join(root, "tree"), 0o755);
  chmodSync(gitDir, 0o755);
  chmodSync(join(gitDir, "config"), 0o644);
  log = vi.fn();
  readVersion.mockReset();
  readVersion.mockResolvedValue({ major: 2, minor: 51, patch: 0 });
  spawnMock.mockReset();
  vi.mocked(lstat).mockImplementation(async (path, options) => {
    const reading = (await actualFs.lstat(path, options)) as Stats;
    return foreignPaths.has(String(path))
      ? Object.assign(Object.create(Object.getPrototypeOf(reading) as object) as Stats, reading, {
          uid: reading.uid + 1,
        })
      : reading;
  });
});

afterEach(() => {
  foreignPaths.clear();
  vi.mocked(lstat).mockReset();
  spawnMock.mockReset();
  readVersion.mockReset();
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function floorAt(dir: string, daemon?: DaemonPaths): Floor {
  return {
    vaultFiles: [join(dir, "vault.db"), join(dir, "session.json")],
    ...(daemon !== undefined ? { daemon } : {}),
  };
}

function calls(): SpawnCall[] {
  return spawnMock.mock.calls as SpawnCall[];
}

function refusedRow(
  operation: TreeOperation,
  over: Record<string, unknown> = { transport: "https" },
) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: {
      context: "git",
      operation,
      ...over,
      error: "INVALID_GIT_CONFIG",
      network_isolation: false,
      fs_isolation: false,
    },
    success: false,
  };
}

describe.skipIf(WIN32 || GIT === null)(
  "the repository's owner judged before any git step, scripted (POSIX only: on win32 git's own check stands in the owner's place; skipped where no supported git resolves)",
  () => {
    const tree = () => join(root, "tree");
    const config = () => join(root, "tree", ".git", "config");
    let sshKey: string;

    beforeAll(() => {
      sshKey = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs1", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      }).privateKey;
    });

    function use(
      operation: TreeOperation,
      floor: Floor = floorAt(vaultDir),
      connection: ConnectionConfig | undefined = undefined,
    ) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: HTTPS_REPOSITORY, working_directory: tree() },
        SCRIPTED_SECRET,
        policy(),
        connection,
        "secret-1",
        undefined,
        floor,
      );
    }

    function useWithoutFloor(operation: TreeOperation) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: HTTPS_REPOSITORY, working_directory: tree() },
        SCRIPTED_SECRET,
        policy(),
        undefined,
        "secret-1",
      );
    }

    function useOverSsh(operation: TreeOperation) {
      return new GitInjector({ log } as unknown as AuditLogger).executeWithSecret(
        { type: "git", operation, repository: SSH_REPOSITORY, working_directory: tree() },
        new Uint8Array(Buffer.from(sshKey)),
        policy(),
        KNOWN_HOSTS,
        "secret-1",
        undefined,
        floorAt(vaultDir),
      );
    }

    /** spawnCaptured answers by argv: the probe, a pull's top level, the push's HEAD, the fetch's remote; every other step succeeds. */
    function script(): void {
      const gitDir = join(tree(), ".git");
      spawnMock.mockImplementation((_cmd, args) => {
        const sub = gitSubcommand(args);
        let stdout = "";
        if (args.includes("--git-path")) {
          stdout = `${join(gitDir, "objects")}\n${join(gitDir, "shallow")}\nsha1\n${gitDir}\n${gitDir}\nfalse\n`;
        } else if (args.includes("--show-toplevel")) stdout = `${tree()}\n`;
        else if (sub === "symbolic-ref") stdout = "refs/heads/main\n";
        else if (sub === "config") stdout = "remote.origin.url\0";
        return Promise.resolve({ ...OK_STEP, stdout });
      });
    }

    async function expectRefused(
      run: () => Promise<unknown>,
      message: string,
      row: ReturnType<typeof refusedRow>,
    ): Promise<void> {
      const err = await expectVaultError(run, ErrorCode.INVALID_GIT_CONFIG);
      expect(err.message).toBe(message);
      expect(log.mock.calls).toEqual([[row]]);
      expect(spawnMock).not.toHaveBeenCalled();
    }

    it.each(TREE_OPERATIONS)(
      "a repository whose config is another account's is refused before any git step: %s over HTTPS, with a CA pinned the row carries ca_pinned",
      async (operation) => {
        script();
        foreignPaths.add(config());
        await expectRefused(() => use(operation), OWNER, refusedRow(operation));

        log.mockClear();
        await expectRefused(
          () => use(operation, floorAt(vaultDir), PINNED_CA),
          OWNER,
          refusedRow(operation, { transport: "https", ca_pinned: true }),
        );
      },
    );

    it.skipIf(SSH === null).each(TREE_OPERATIONS)(
      "a repository whose config is another account's is refused before any git step: %s over SSH, the row naming the host (skipped where the native ssh client does not resolve)",
      async (operation) => {
        script();
        foreignPaths.add(config());
        await expectRefused(
          () => useOverSsh(operation),
          OWNER,
          refusedRow(operation, { transport: "ssh", host: SSH_HOST }),
        );
      },
    );

    it.each(TREE_OPERATIONS)(
      "the modes are a daemon's: a top of 0757 is refused for %s with a daemon's floor, and with a floor of no daemon and with no floor the first spawned step is the probe",
      async (operation) => {
        script();
        chmodSync(tree(), 0o757);
        await expectRefused(
          () => use(operation, floorAt(vaultDir, NO_PATHS)),
          CHANGEABLE,
          refusedRow(operation),
        );

        for (const run of [
          () => use(operation, floorAt(vaultDir)),
          () => useWithoutFloor(operation),
        ]) {
          spawnMock.mockClear();
          const result = await run();
          expect(result.exit_code).toBe(0);
          const [, args, opts] = calls()[0] as SpawnCall;
          expect(gitSubcommand(args)).toBe("rev-parse");
          expect(args).toContain("--absolute-git-dir");
          expect(opts.cwd).toBe(tree());
        }
      },
    );

    it.each(TREE_OPERATIONS)(
      "without a floor the owner is still judged: %s in a repository whose config is another account's",
      async (operation) => {
        script();
        foreignPaths.add(config());
        await expectRefused(() => useWithoutFloor(operation), OWNER, refusedRow(operation));
      },
    );
  },
);
