import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, GitAction, GitOperation, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import type { GitVersion, readGitVersion } from "./git-injector-version.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { validateUrl } from "./url-validator.js";
import { system32Path } from "../win32-paths.js";
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
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(async (urlStr: string) => {
      const url = new URL(urlStr);
      if (url.hostname === "git.example") {
        return { url, resolvedAddresses: ["93.184.216.34", "2606:2800:220:1::1"] };
      }
      if (url.hostname === "ipv4.git.example") {
        return { url, resolvedAddresses: ["93.184.216.34"] };
      }
      if (["127.0.0.1", "localhost", "8.8.8.8", "8.8.4.4"].includes(url.hostname)) {
        return actual.validateUrl(urlStr);
      }
      throw new Error(`unexpected host ${url.hostname}`);
    }),
  };
});

const { readGitVersion: realReadGitVersion } = await vi.importActual<
  typeof import("./git-injector-version.js")
>("./git-injector-version.js");

if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");
const SYSTEM_TMP = tmpdir();
const WIN32 = process.platform === "win32";

const OPERATIONS = ["clone", "pull", "push", "fetch", "ls-remote"] as const;
const UNFLOORED: readonly GitOperation[] = WIN32 ? ["clone", "ls-remote"] : OPERATIONS;
const WIN32_FLOORED = ["pull", "push", "fetch"] as const;
const PLANS: Record<GitOperation, readonly string[]> = {
  clone: ["network", "network", "local"],
  "ls-remote": ["network"],
  pull: ["local", "local", "local", "network", "local", "local"],
  push: ["local", "local", "local", "network"],
  fetch: ["local", "local", "local", "network", "local", "local"],
};

const RESOLVED_HOST = "https://git.example/org/repo.git";
const LOOPBACK_ADDRESS = "http://127.0.0.1/org/repo.git";
const IP_LITERAL = "https://8.8.8.8/org/repo.git";
const LOOPBACK_NAME = "http://localhost/org/repo.git";
const SSH_REPOSITORY = "git@allowed.invalid:org/repo.git";
const SSH_HOST = "allowed.invalid";
const PIN_443 = "-c http.curloptResolve=git.example:443:93.184.216.34,[2606:2800:220:1::1]";

const HTTPS_CREDENTIAL = new Uint8Array(Buffer.from("git-user:s3cret-token-value"));

const PINNED: ConnectionConfig = {
  ssh: { known_hosts: ["allowed.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};

const ALLOWLISTED = "HARPOC_TEST_GIT_VERSION_ALLOWLISTED";
const BASE_ENV_KEYS = [
  ALLOWLISTED,
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_NOSYSTEM",
  "PATH",
  ...(process.platform === "win32" ? ["SystemRoot"] : []),
].sort();

const UNREADABLE = "Git operation failed: git's version could not be read";

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

const FLOOR_HTTPS: ReadonlyArray<readonly [string, string]> = [
  ["HTTPS to a host the vault resolved", RESOLVED_HOST],
  ["HTTP to a loopback address", LOOPBACK_ADDRESS],
];

const UNPINNED_HTTPS: ReadonlyArray<readonly [string, string]> = [
  ["HTTPS to an IP literal", IP_LITERAL],
  ["HTTP to a loopback name", LOOPBACK_NAME],
];

function olderThanFloor(version: string): string {
  return `Git operation failed: git ${version} is older than 2.32, which the git context needs`;
}

function olderThanPinFloor(version: string): string {
  return `Git operation failed: git ${version} is older than 2.37 and would ignore the addresses the vault judged for the repository host`;
}

function olderThanWin32Floor(version: string): string {
  return `Git operation failed: git ${version} is older than 2.37.1, which a pull, a push and a fetch need on Windows`;
}

function gitVersion(major: number, minor: number, patch: number): GitVersion {
  return { major, minor, patch };
}

function overOperations(
  addresses: ReadonlyArray<readonly [string, string]>,
): Array<[GitOperation, string, string]> {
  return OPERATIONS.flatMap((operation) =>
    addresses.map(([label, repository]): [GitOperation, string, string] => [
      operation,
      label,
      repository,
    ]),
  );
}

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [
      "https://git.example/*",
      "https://ipv4.git.example/*",
      "http://127.0.0.1/*",
      "https://8.8.8.8/*",
      "http://localhost/*",
    ],
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
    ssh_bootstrap: null,
    ...overrides,
  };
}

/** `dir` holding a `.git` with a git directory's shape: `HEAD`, `objects`, `refs`. */
function repository(dir: string): string {
  mkdirSync(join(dir, ".git", "objects"), { recursive: true });
  mkdirSync(join(dir, ".git", "refs"));
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  return dir;
}

const spawnMock = vi.mocked(spawnCaptured);
let scratch: string;
let tempRoot: string;
let savedTemp: { TMPDIR?: string; TMP?: string; TEMP?: string };
let log: Mock;
let sshKey: string;

beforeAll(() => {
  sshKey = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }).privateKey;
});

beforeEach(() => {
  scratch = repository(mkdtempSync(join(SYSTEM_TMP, "harpoc-git-vf-wd-")));
  tempRoot = mkdtempSync(join(SYSTEM_TMP, "harpoc-git-vf-"));
  savedTemp = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = tempRoot;
  process.env.TMP = tempRoot;
  process.env.TEMP = tempRoot;
  process.env.HARPOC_TEST_GIT_VERSION_ALLOWLISTED = "allowlisted";
  log = vi.fn();
  readVersion.mockReset();
  vi.mocked(validateUrl).mockClear();
  spawnMock.mockReset();
  spawnMock.mockImplementation((_cmd, args) => {
    const sub = gitSubcommand(args);
    const stdout = args.includes("--show-toplevel")
      ? `${scratch}\n`
      : sub === "rev-parse"
        ? `${join(scratch, ".git", "objects")}\n${join(scratch, ".git", "shallow")}\nsha1\n${join(scratch, ".git")}\n${join(scratch, ".git")}\nfalse\n`
        : sub === "symbolic-ref"
          ? "refs/heads/main\n"
          : sub === "config"
            ? "remote.origin.url\0"
            : "";
    return Promise.resolve({ ...OK_RESULT, stdout });
  });
});

afterEach(() => {
  if (savedTemp.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = savedTemp.TMPDIR;
  if (savedTemp.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = savedTemp.TMP;
  if (savedTemp.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = savedTemp.TEMP;
  delete process.env.HARPOC_TEST_GIT_VERSION_ALLOWLISTED;
  spawnMock.mockReset();
  readVersion.mockReset();
  rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function injector(): GitInjector {
  return new GitInjector({ log } as unknown as AuditLogger);
}

function actionFor(
  operation: GitOperation,
  repository: string,
  patch: Partial<GitAction> = {},
): GitAction {
  const tree = operation === "pull" || operation === "push" || operation === "fetch";
  return {
    type: "git",
    operation,
    repository,
    ...(tree ? { working_directory: scratch } : {}),
    ...patch,
  };
}

function secretFor(repository: string): Uint8Array {
  return repository.startsWith("git@") ? new Uint8Array(Buffer.from(sshKey)) : HTTPS_CREDENTIAL;
}

function use(
  action: GitAction,
  usePolicy: InjectionPolicy = policy(),
  secret: Uint8Array = secretFor(action.repository),
  engine: GitInjector = injector(),
  config: ConnectionConfig = PINNED,
) {
  return engine.executeWithSecret(action, secret, usePolicy, config, "secret-1");
}

function auditRow(detail: Record<string, unknown>, success: boolean) {
  return {
    eventType: "secret.use",
    secretId: "secret-1",
    detail: { context: "git", ...detail },
    success,
  };
}

function stepKinds(): string[] {
  return spawnMock.mock.calls.map(([, args]) =>
    args.some((a) => a.startsWith("--git-dir=")) ? "network" : "local",
  );
}

function pinsOfSteps(): string[][] {
  return spawnMock.mock.calls.map(([, args]) =>
    args.flatMap((a, i) => (a.includes("curloptResolve") ? [`${String(args[i - 1])} ${a}`] : [])),
  );
}

async function expectFloorRefusal(
  action: GitAction,
  message: string,
  detail: Record<string, unknown>,
  usePolicy: InjectionPolicy = policy(),
  secret: Uint8Array = secretFor(action.repository),
): Promise<void> {
  const err = await expectVaultError(
    () => use(action, usePolicy, secret),
    ErrorCode.GIT_OPERATION_FAILED,
  );
  expect(err.message === message).toBe(true);
  expect(log.mock.calls).toEqual([[auditRow(detail, false)]]);
  expect(Object.keys((log.mock.calls[0]?.[0] as AuditLogOptions).detail ?? {})).toEqual([
    "context",
    ...Object.keys(detail),
  ]);
  expect(spawnMock).not.toHaveBeenCalled();
  expect(readdirSync(tempRoot)).toEqual([]);
}

async function expectRuns(action: GitAction, successDetail: Record<string, unknown>) {
  const result = await use(action);
  expect(result.exit_code).toBe(0);
  expect(stepKinds()).toEqual(PLANS[action.operation]);
  expect(log.mock.calls).toEqual([
    [auditRow({ operation: action.operation, ...successDetail }, true)],
  ]);
}

const HTTPS_SUCCESS = {
  transport: "https",
  exit_code: 0,
  network_isolation: false,
  fs_isolation: false,
};

const SSH_SUCCESS = {
  transport: "ssh",
  host: SSH_HOST,
  exit_code: 0,
  network_isolation: false,
  fs_isolation: false,
};

function expectReadsUnderBaseEnv(count: number): void {
  expect(readVersion.mock.calls.map(([path]) => path)).toEqual(
    Array<string>(count).fill(GIT as string),
  );
  for (const [, env] of readVersion.mock.calls) {
    expect(Object.keys(env).sort()).toEqual(BASE_ENV_KEYS);
    expect(env[ALLOWLISTED]).toBe("allowlisted");
  }
}

describe.skipIf(GIT === null)(
  "U-2: a git older than 2.32 is refused on every use, on both transports (skipped where git does not resolve)",
  () => {
    it.each(overOperations(FLOOR_HTTPS))(
      "%s over %s with git 2.31.9: GIT_OPERATION_FAILED with the 2.32 floor's message, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory",
      async (operation, _label, repository) => {
        readVersion.mockResolvedValue(gitVersion(2, 31, 9));
        await expectFloorRefusal(actionFor(operation, repository), olderThanFloor("2.31.9"), {
          operation,
          error: "GIT_OPERATION_FAILED",
          git_version: "2.31.9",
        });
      },
    );

    it.skipIf(SSH === null).each(OPERATIONS)(
      "%s over SSH with git 2.31.9: GIT_OPERATION_FAILED with the 2.32 floor's message, one failed row of context, operation, host, error and git_version, nothing spawned, no temporary directory (skipped where the native ssh client does not resolve)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 31, 9));
        await expectFloorRefusal(actionFor(operation, SSH_REPOSITORY), olderThanFloor("2.31.9"), {
          operation,
          host: SSH_HOST,
          error: "GIT_OPERATION_FAILED",
          git_version: "2.31.9",
        });
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "control: git 2.32.0 runs where no pin is handed (skipped where git does not resolve)",
  () => {
    it.each(UNFLOORED)(
      "%s over HTTP to a loopback address with git 2.32.0: the operation's plan spawned step by step and one success row of the unchanged form",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 32, 0));
        await expectRuns(actionFor(operation, LOOPBACK_ADDRESS), HTTPS_SUCCESS);
      },
    );

    it.skipIf(SSH === null).each(UNFLOORED)(
      "%s over SSH with git 2.32.0: the operation's plan spawned step by step and one success row of the unchanged form (skipped where the native ssh client does not resolve)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 32, 0));
        await expectRuns(actionFor(operation, SSH_REPOSITORY), SSH_SUCCESS);
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "U-3: a git from 2.32 and below 2.37 is refused for HTTPS to a host the vault resolved (skipped where git does not resolve)",
  () => {
    it.each(OPERATIONS)(
      "%s over HTTPS to a host the vault resolved with git 2.36.9: refused after exactly one validateUrl call, GIT_OPERATION_FAILED with the 2.37 floor's message, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 36, 9));
        await expectFloorRefusal(actionFor(operation, RESOLVED_HOST), olderThanPinFloor("2.36.9"), {
          operation,
          error: "GIT_OPERATION_FAILED",
          git_version: "2.36.9",
        });
        expect(vi.mocked(validateUrl)).toHaveBeenCalledTimes(1);
      },
    );

    it.each(overOperations(UNPINNED_HTTPS).filter(([operation]) => UNFLOORED.includes(operation)))(
      "control: %s over %s with git 2.36.9: the operation's plan spawned step by step without a pin and one success row of the unchanged form",
      async (operation, _label, repository) => {
        readVersion.mockResolvedValue(gitVersion(2, 36, 9));
        await expectRuns(actionFor(operation, repository), HTTPS_SUCCESS);
        expect(pinsOfSteps()).toEqual(PLANS[operation].map(() => []));
      },
    );

    it.skipIf(SSH === null).each(UNFLOORED)(
      "control: %s over SSH with git 2.36.9: the operation's plan spawned step by step and one success row of the unchanged form (skipped where the native ssh client does not resolve)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 36, 9));
        await expectRuns(actionFor(operation, SSH_REPOSITORY), SSH_SUCCESS);
      },
    );

    it.each(UNFLOORED)(
      "control: %s over HTTPS to a host the vault resolved with git 2.37.0: the operation's plan spawned step by step, every network step handed the pin of both judged addresses and every local step none, one success row of the unchanged form",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 0));
        await expectRuns(actionFor(operation, RESOLVED_HOST), HTTPS_SUCCESS);
        expect(pinsOfSteps()).toEqual(
          PLANS[operation].map((kind) => (kind === "network" ? [PIN_443] : [])),
        );
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "W-1: on Windows a pull, a push and a fetch need git 2.37.1 (skipped where git does not resolve)",
  () => {
    it.runIf(WIN32).each(WIN32_FLOORED)(
      "%s over HTTP to a loopback address with git 2.37.0: GIT_OPERATION_FAILED with the Windows floor's message, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory (win32 only)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 0));
        await expectFloorRefusal(
          actionFor(operation, LOOPBACK_ADDRESS),
          olderThanWin32Floor("2.37.0"),
          { operation, error: "GIT_OPERATION_FAILED", git_version: "2.37.0" },
        );
      },
    );

    it.runIf(WIN32 && SSH !== null).each(WIN32_FLOORED)(
      "%s over SSH with git 2.37.0: GIT_OPERATION_FAILED with the Windows floor's message, one failed row of context, operation, host, error and git_version, nothing spawned, no temporary directory (win32 only, skipped where the native ssh client does not resolve)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 0));
        await expectFloorRefusal(
          actionFor(operation, SSH_REPOSITORY),
          olderThanWin32Floor("2.37.0"),
          { operation, host: SSH_HOST, error: "GIT_OPERATION_FAILED", git_version: "2.37.0" },
        );
      },
    );

    it.runIf(WIN32).each(WIN32_FLOORED)(
      "%s over HTTPS to a host the vault resolved with git 2.37.0: the pin's floor passes, refused after exactly one validateUrl call with the Windows floor's message, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory (win32 only)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 0));
        await expectFloorRefusal(
          actionFor(operation, RESOLVED_HOST),
          olderThanWin32Floor("2.37.0"),
          {
            operation,
            error: "GIT_OPERATION_FAILED",
            git_version: "2.37.0",
          },
        );
        expect(vi.mocked(validateUrl)).toHaveBeenCalledTimes(1);
      },
    );

    it
      .runIf(WIN32)
      .each(overOperations(UNPINNED_HTTPS).filter(([operation]) => !UNFLOORED.includes(operation)))(
      "%s over %s with git 2.36.9: no pin, so the Windows floor's message, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory (win32 only)",
      async (operation, _label, repository) => {
        readVersion.mockResolvedValue(gitVersion(2, 36, 9));
        await expectFloorRefusal(actionFor(operation, repository), olderThanWin32Floor("2.36.9"), {
          operation,
          error: "GIT_OPERATION_FAILED",
          git_version: "2.36.9",
        });
      },
    );

    it.runIf(WIN32 && SSH !== null).each(WIN32_FLOORED)(
      "%s over SSH with git 2.36.9: the Windows floor's message, one failed row of context, operation, host, error and git_version, nothing spawned, no temporary directory (win32 only, skipped where the native ssh client does not resolve)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 36, 9));
        await expectFloorRefusal(
          actionFor(operation, SSH_REPOSITORY),
          olderThanWin32Floor("2.36.9"),
          { operation, host: SSH_HOST, error: "GIT_OPERATION_FAILED", git_version: "2.36.9" },
        );
      },
    );

    it.runIf(WIN32).each(WIN32_FLOORED)(
      "control: %s over HTTP to a loopback address with git 2.37.1: the operation's plan spawned step by step and one success row of the unchanged form (win32 only)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 1));
        await expectRuns(actionFor(operation, LOOPBACK_ADDRESS), HTTPS_SUCCESS);
      },
    );

    it.runIf(WIN32).each(WIN32_FLOORED)(
      "control: %s over HTTPS to a host the vault resolved with git 2.37.1: the operation's plan spawned step by step, every network step handed the pin of both judged addresses and every local step none, one success row of the unchanged form (win32 only)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 1));
        await expectRuns(actionFor(operation, RESOLVED_HOST), HTTPS_SUCCESS);
        expect(pinsOfSteps()).toEqual(
          PLANS[operation].map((kind) => (kind === "network" ? [PIN_443] : [])),
        );
      },
    );

    it.runIf(WIN32 && SSH !== null).each(WIN32_FLOORED)(
      "control: %s over SSH with git 2.37.1: the operation's plan spawned step by step and one success row of the unchanged form (win32 only, skipped where the native ssh client does not resolve)",
      async (operation) => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 1));
        await expectRuns(actionFor(operation, SSH_REPOSITORY), SSH_SUCCESS);
      },
    );

    it.runIf(WIN32)(
      "a pull without a working tree, with git 2.37.0: the Windows floor's refusal, not the working tree's, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory (win32 only)",
      async () => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 0));
        await expectFloorRefusal(
          { type: "git", operation: "pull", repository: LOOPBACK_ADDRESS },
          olderThanWin32Floor("2.37.0"),
          { operation: "pull", error: "GIT_OPERATION_FAILED", git_version: "2.37.0" },
        );
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "a git whose version cannot be read is refused (skipped where git does not resolve)",
  () => {
    it.each(overOperations(FLOOR_HTTPS))(
      "%s over %s with an unreadable version: GIT_OPERATION_FAILED with the unreadable version's message, one failed row of context, operation and error without git_version, nothing spawned, no temporary directory",
      async (operation, _label, repository) => {
        readVersion.mockResolvedValue(null);
        await expectFloorRefusal(actionFor(operation, repository), UNREADABLE, {
          operation,
          error: "GIT_OPERATION_FAILED",
        });
      },
    );

    it.skipIf(SSH === null).each(OPERATIONS)(
      "%s over SSH with an unreadable version: GIT_OPERATION_FAILED with the unreadable version's message, one failed row of context, operation, host and error without git_version, nothing spawned, no temporary directory (skipped where the native ssh client does not resolve)",
      async (operation) => {
        readVersion.mockResolvedValue(null);
        await expectFloorRefusal(actionFor(operation, SSH_REPOSITORY), UNREADABLE, {
          operation,
          host: SSH_HOST,
          error: "GIT_OPERATION_FAILED",
        });
      },
    );
  },
);

const REFUSED_BEFORE_THE_READ: ReadonlyArray<
  readonly [string, GitAction, Partial<InjectionPolicy>, ErrorCode, Record<string, unknown>]
> = [
  [
    "a denied argument",
    { type: "git", operation: "clone", repository: RESOLVED_HOST, args: ["--upload-pack=x"] },
    {},
    ErrorCode.INVALID_GIT_CONFIG,
    { operation: "clone", error: "INVALID_GIT_CONFIG" },
  ],
  [
    "a URL outside the allowlist",
    { type: "git", operation: "clone", repository: "https://8.8.4.4/org/repo.git" },
    {},
    ErrorCode.URL_NOT_ALLOWED,
    { operation: "clone", error: "URL_NOT_ALLOWED" },
  ],
  [
    "an IP version the judged addresses lack",
    {
      type: "git",
      operation: "clone",
      repository: "https://ipv4.git.example/org/repo.git",
      args: ["--ipv6"],
    },
    {},
    ErrorCode.INVALID_GIT_CONFIG,
    { operation: "clone", error: "INVALID_GIT_CONFIG" },
  ],
  [
    "an SSH host outside the allowlist",
    { type: "git", operation: "clone", repository: "git@other.invalid:org/repo.git" },
    {},
    ErrorCode.HOST_NOT_ALLOWED,
    { operation: "clone", host: "other.invalid", error: "HOST_NOT_ALLOWED" },
  ],
  [
    "a git outside command_allowlist",
    { type: "git", operation: "clone", repository: RESOLVED_HOST },
    { command_allowlist: [] },
    ErrorCode.COMMAND_NOT_ALLOWED,
    { operation: "clone", error: "COMMAND_NOT_ALLOWED" },
  ],
];

describe.skipIf(GIT === null)(
  "the read's place: after the input refusals and the IP-version refusal, before the working tree and the key (skipped where git does not resolve)",
  () => {
    it.each(REFUSED_BEFORE_THE_READ)(
      "%s with git 2.31.9: its own code and one failed row of its own, the reader never called, nothing spawned",
      async (_label, action, overrides, code, detail) => {
        readVersion.mockResolvedValue(gitVersion(2, 31, 9));
        await expectVaultError(() => use(action, policy(overrides)), code);
        expect(log.mock.calls).toEqual([[auditRow(detail, false)]]);
        expect(readVersion).not.toHaveBeenCalled();
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it("an SSH clone whose connection config has no known_hosts, with git 2.31.9: SSH_NOT_CONFIGURED and one failed row of context, operation, host and error without git_version, the reader never called, nothing spawned", async () => {
      readVersion.mockResolvedValue(gitVersion(2, 31, 9));
      await expectVaultError(
        () =>
          use(
            actionFor("clone", SSH_REPOSITORY),
            policy(),
            secretFor(SSH_REPOSITORY),
            injector(),
            {},
          ),
        ErrorCode.SSH_NOT_CONFIGURED,
      );
      expect(log.mock.calls).toEqual([
        [auditRow({ operation: "clone", host: SSH_HOST, error: "SSH_NOT_CONFIGURED" }, false)],
      ]);
      expect(readVersion).not.toHaveBeenCalled();
      expect(spawnMock).not.toHaveBeenCalled();
    });

    it("a pull without a working tree, with git 2.31.9: the 2.32 floor's refusal, not the working tree's, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory", async () => {
      readVersion.mockResolvedValue(gitVersion(2, 31, 9));
      await expectFloorRefusal(
        { type: "git", operation: "pull", repository: LOOPBACK_ADDRESS },
        olderThanFloor("2.31.9"),
        { operation: "pull", error: "GIT_OPERATION_FAILED", git_version: "2.31.9" },
      );
    });

    it.skipIf(SSH === null)(
      "an SSH clone with a key that does not parse, with git 2.31.9: the 2.32 floor's refusal, not the agent's, one failed row of context, operation, host, error and git_version, nothing spawned, no temporary directory (skipped where the native ssh client does not resolve)",
      async () => {
        readVersion.mockResolvedValue(gitVersion(2, 31, 9));
        await expectFloorRefusal(
          actionFor("clone", SSH_REPOSITORY),
          olderThanFloor("2.31.9"),
          {
            operation: "clone",
            host: SSH_HOST,
            error: "GIT_OPERATION_FAILED",
            git_version: "2.31.9",
          },
          policy(),
          new Uint8Array(Buffer.from("not-a-key")),
        );
      },
    );
  },
);

describe.skipIf(GIT === null)(
  "C-13: the version is read on every use, from the resolved git, under the use's own base environment (skipped where git does not resolve)",
  () => {
    it("two HTTPS uses of one injector read the version twice, each from the resolved git under the policy's allowlisted variable and no askpass or credential variable", async () => {
      readVersion.mockResolvedValue(gitVersion(2, 37, 0));
      const engine = injector();
      const allowing = policy({ env_allowlist: [ALLOWLISTED] });
      await use(actionFor("clone", RESOLVED_HOST), allowing, HTTPS_CREDENTIAL, engine);
      await use(actionFor("clone", RESOLVED_HOST), allowing, HTTPS_CREDENTIAL, engine);
      expectReadsUnderBaseEnv(2);
    });

    it.skipIf(SSH === null)(
      "two SSH uses of one injector read the version twice, each from the resolved git under the policy's allowlisted variable and no agent or credential variable (skipped where the native ssh client does not resolve)",
      async () => {
        readVersion.mockResolvedValue(gitVersion(2, 37, 0));
        const engine = injector();
        const allowing = policy({ env_allowlist: [ALLOWLISTED] });
        await use(actionFor("clone", SSH_REPOSITORY), allowing, secretFor(SSH_REPOSITORY), engine);
        await use(actionFor("clone", SSH_REPOSITORY), allowing, secretFor(SSH_REPOSITORY), engine);
        expectReadsUnderBaseEnv(2);
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "end to end through the real reader, a stand-in git first on PATH (POSIX only: on win32 the resolver takes .exe and .com alone and a #!/bin/sh stand-in cannot be spawned shell-free)",
  () => {
    const savedPath = process.env.PATH;
    let bin: string;
    let standIn: string;

    beforeEach(() => {
      bin = realpathSync(mkdtempSync(join(SYSTEM_TMP, "harpoc-git-vf-bin-")));
      standIn = join(bin, "git");
      process.env.PATH = `${bin}${delimiter}${savedPath ?? ""}`;
      readVersion.mockImplementation(realReadGitVersion);
    });

    afterEach(() => {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
      rmSync(bin, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function standInPrinting(line: string): InjectionPolicy {
      writeFileSync(standIn, `#!/bin/sh\necho '${line}'\n`);
      chmodSync(standIn, 0o755);
      return policy({ command_allowlist: [standIn] });
    }

    it.each(OPERATIONS)(
      "%s over HTTP to a loopback address, the stand-in printing git version 2.30.2: the real reader runs the stand-in, GIT_OPERATION_FAILED with the 2.32 floor's message, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory",
      async (operation) => {
        const usePolicy = standInPrinting("git version 2.30.2");
        await expectFloorRefusal(
          actionFor(operation, LOOPBACK_ADDRESS),
          olderThanFloor("2.30.2"),
          { operation, error: "GIT_OPERATION_FAILED", git_version: "2.30.2" },
          usePolicy,
        );
        expect(readVersion.mock.calls.map(([path]) => path)).toEqual([standIn]);
      },
    );

    it.skipIf(SSH === null).each(OPERATIONS)(
      "%s over SSH, the stand-in printing git version 2.30.2: the real reader runs the stand-in, GIT_OPERATION_FAILED with the 2.32 floor's message, one failed row of context, operation, host, error and git_version, nothing spawned, no temporary directory (skipped where the native ssh client does not resolve)",
      async (operation) => {
        const usePolicy = standInPrinting("git version 2.30.2");
        await expectFloorRefusal(
          actionFor(operation, SSH_REPOSITORY),
          olderThanFloor("2.30.2"),
          { operation, host: SSH_HOST, error: "GIT_OPERATION_FAILED", git_version: "2.30.2" },
          usePolicy,
        );
        expect(readVersion.mock.calls.map(([path]) => path)).toEqual([standIn]);
      },
    );

    it.each(OPERATIONS)(
      "%s over HTTPS to a host the vault resolved, the stand-in printing git version 2.36.6: the real reader runs the stand-in, GIT_OPERATION_FAILED with the 2.37 floor's message, one failed row of context, operation, error and git_version, nothing spawned, no temporary directory",
      async (operation) => {
        const usePolicy = standInPrinting("git version 2.36.6");
        await expectFloorRefusal(
          actionFor(operation, RESOLVED_HOST),
          olderThanPinFloor("2.36.6"),
          { operation, error: "GIT_OPERATION_FAILED", git_version: "2.36.6" },
          usePolicy,
        );
        expect(readVersion.mock.calls.map(([path]) => path)).toEqual([standIn]);
      },
    );
  },
);
