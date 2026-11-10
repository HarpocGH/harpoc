/**
 * Hard rule 7 (RX-B9-12): every refusal the git injector throws before its
 * credential-bearing step writes exactly one failed `secret.use` row, in the
 * form of the injector's neighbouring audited refusals — `{ context: "git",
 * operation, error }` (plus `host` on SSH, `transport` once the plan runs) —
 * never the refused argument, refspec or path. The spawn seam is mocked: the
 * working-tree probes of the one in-plan row run real git, nothing else spawns.
 */
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

// The SSH row resolves ssh as the injector does; on Windows only the native
// Win32-OpenSSH client is accepted, so its directory leads the PATH (as in
// git-injector.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");
// Skipped where git (and, for the SSH row, the native ssh client) does not resolve.
const describeGit = describe.skipIf(GIT === null);
const describeGitSsh = describe.skipIf(GIT === null || SSH === null);

const NULL_GIT_CONFIG = process.platform === "win32" ? "NUL" : "/dev/null";
const REPO = "https://8.8.8.8/org/repo.git";
const SECRET = new Uint8Array(Buffer.from("git-user:s3cret-token-value"));

const { spawnCaptured: realSpawnCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");

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
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
    ...overrides,
  };
}

/**
 * The action as an unparsed caller (`VaultEngine.useSecret`, the SDK's
 * `DirectClient.useSecret`) hands it to the injector: the schema never saw
 * it, so the operation may be any string — hence the cast.
 */
function unparsed(operation: string, patch: Record<string, unknown> = {}): GitAction {
  return { type: "git", operation, repository: REPO, ...patch } as unknown as GitAction;
}

function recorder() {
  const log = vi.fn();
  return { log, injector: new GitInjector({ log } as unknown as AuditLogger) };
}

const failedRow = (detail: Record<string, unknown>) => ({
  eventType: "secret.use",
  secretId: "secret-1",
  detail: { context: "git", ...detail },
  success: false,
});

const ATTRIBUTION: AuditAttribution = {
  principal_type: "agent",
  principal_id: "alice",
  session_id: "sess-attr-1",
  interface: "rest",
};

function expectOneFailedUse(log: Mock, code: string): AuditLogOptions {
  const all = log.mock.calls.map((c) => c[0] as AuditLogOptions);
  expect(all).toHaveLength(1);
  const [row] = all;
  expect(row?.eventType).toBe("secret.use");
  expect(row?.success).toBe(false);
  expect(row?.detail?.error).toBe(code);
  return row as AuditLogOptions;
}

function expectAttributed(row: AuditLogOptions): void {
  expect(row.principalType).toBe("agent");
  expect(row.principalId).toBe("alice");
  expect(row.sessionId).toBe("sess-attr-1");
  expect(row.detail?.interface).toBe("rest");
}

describe("RX-B9-12: a pre-flight refusal writes one failed secret.use row and nothing spawns", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  async function expectRefusedWithOneRow(
    operation: string,
    patch: Record<string, unknown>,
    message: string,
  ): Promise<void> {
    const { log, injector } = recorder();
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          unparsed(operation, patch),
          SECRET,
          policy(),
          undefined,
          "secret-1",
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe(message);
    expect(log.mock.calls).toEqual([[failedRow({ operation, error: "INVALID_GIT_CONFIG" })]]);
    expect(spawnMock).not.toHaveBeenCalled();
  }

  it.each<[string, Record<string, unknown>, string]>([
    ["clone", { args: ["--upload-pack=/x"] }, "disallowed git argument: --upload-pack=/x"],
    ["pull", { args: ["--conf=k=v"] }, "disallowed git argument: --conf=k=v"],
    ["push", { args: ["-u"] }, "disallowed git argument: -u"],
    ["fetch", { args: ["--multiple"] }, "disallowed git argument: --multiple"],
    ["ls-remote", { args: ["-u"] }, "disallowed git argument: -u"],
    [
      "clone",
      { args: ["https://8.8.4.4/x.git"] },
      "a clone without working_directory takes no positional argument: https://8.8.4.4/x.git",
    ],
    ["pull", { args: ["origin"] }, "a pull takes no positional argument: origin"],
    ["push", { args: ["main"] }, "a push takes no positional argument: main"],
    ["fetch", { args: ["origin"] }, "a fetch takes no positional argument: origin"],
    ["ls-remote", { args: ["origin"] }, "an ls-remote takes no positional argument: origin"],
    ["clone", { working_directory: "-x" }, "working_directory must not start with '-'"],
    ["pull", { working_directory: "--upload-pack=x" }, "working_directory must not start with '-'"],
    ["push", { working_directory: "-c" }, "working_directory must not start with '-'"],
    ["clone", { refspecs: ["refs/heads/main"] }, "refspecs is only accepted by a fetch"],
    [
      "fetch",
      { refspecs: ["refs/heads/a:refs/heads/b"] },
      "unsupported fetch refspec: refs/heads/a:refs/heads/b",
    ],
    ["fetch", { refspecs: [] }, "refspecs must not be empty"],
    ["bogus", {}, "unsupported git operation"],
    ["constructor", {}, "unsupported git operation"],
    ["toString", {}, "unsupported git operation"],
  ])("%s %j is refused with one row", expectRefusedWithOneRow);

  it.each<[string, unknown]>([
    ["an array", ["pull"]],
    ["a String object", new String("push")],
  ])("an operation that is not a string (%s) is refused with one row", (_label, operation) =>
    expectRefusedWithOneRow(operation as string, {}, "unsupported git operation"),
  );

  it("the row carries the caller's attribution", async () => {
    const { log, injector } = recorder();
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          unparsed("clone", { args: ["--upload-pack=/x"] }),
          SECRET,
          policy(),
          undefined,
          "secret-1",
          ATTRIBUTION,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expectAttributed(expectOneFailedUse(log, "INVALID_GIT_CONFIG"));
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("a non-VaultError from the pre-flight writes no injector row", async () => {
    const { log, injector } = recorder();
    let thrown: unknown;
    try {
      await injector.executeWithSecret(
        unparsed("pull", { args: [7] }),
        SECRET,
        policy(),
        undefined,
        "secret-1",
      );
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown).not.toBeInstanceOf(VaultError);
    expect(log).not.toHaveBeenCalled();
    expect(spawnMock).not.toHaveBeenCalled();
  });
});

describeGit("RX-B9-12: a working-tree refusal writes one failed row in its function's form", () => {
  const spawnMock = vi.mocked(spawnCaptured);
  let scratch: string;

  beforeEach(() => {
    scratch = mkdtempSync(join(tmpdir(), "harpoc-git-audit-"));
    spawnMock.mockReset();
  });

  afterEach(() => {
    rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const httpsPolicy = () =>
    policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] });

  it.each<[string, (dir: string) => Record<string, unknown>, string]>([
    ["pull", () => ({}), "working_directory is required for pull"],
    ["fetch", () => ({}), "working_directory is required for fetch"],
    [
      "push",
      (dir) => ({ working_directory: join(dir, "absent") }),
      "working_directory does not exist: ",
    ],
    [
      "ls-remote",
      (dir) => ({ working_directory: dir }),
      "working_directory is not accepted by ls-remote",
    ],
  ])(
    "HTTPS %s: the row carries the code alone, never the path",
    async (operation, patch, message) => {
      const { log, injector } = recorder();
      const action = unparsed(operation, patch(scratch));
      const err = await expectVaultError(
        () => injector.executeWithSecret(action, SECRET, httpsPolicy(), undefined, "secret-1"),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message.startsWith(message)).toBe(true);
      expect(log.mock.calls).toEqual([[failedRow({ operation, error: "INVALID_GIT_CONFIG" })]]);
      expect(spawnMock).not.toHaveBeenCalled();
    },
  );

  it("HTTPS: the row carries the caller's attribution", async () => {
    const { log, injector } = recorder();
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          unparsed("pull"),
          SECRET,
          httpsPolicy(),
          undefined,
          "secret-1",
          ATTRIBUTION,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expectAttributed(expectOneFailedUse(log, "INVALID_GIT_CONFIG"));
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("a fetch refused by the remote lookup writes one failed row with the transport (inside the plan)", async () => {
    spawnMock.mockImplementation((cmd, args, opts) =>
      ["fetch", "ls-remote"].includes(gitSubcommand(args) ?? "")
        ? Promise.resolve(OK_RESULT)
        : realSpawnCaptured(cmd, args, opts),
    );
    const wd = join(scratch, "wd");
    execFileSync(GIT as string, ["init", "-q", wd], {
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG },
    });
    const { log, injector } = recorder();
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "fetch", repository: REPO, working_directory: wd },
          SECRET,
          httpsPolicy(),
          undefined,
          "secret-1",
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe(`no remote of the working tree has the URL ${REPO}`);
    expect(log.mock.calls).toEqual([
      [
        failedRow({
          operation: "fetch",
          transport: "https",
          error: "INVALID_GIT_CONFIG",
          network_isolation: false,
          fs_isolation: false,
        }),
      ],
    ]);
  });
});

describeGitSsh("RX-B9-12: an SSH working-tree refusal carries the host like its neighbours", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("push without working_directory: { host, error }, no agent started, nothing spawned", async () => {
    const { log, injector } = recorder();
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
    };
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "push", repository: "git@github.com:org/repo.git" },
          new Uint8Array(Buffer.from("not-a-key")),
          policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
          config,
          "secret-1",
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe("working_directory is required for push");
    expect(log.mock.calls).toEqual([
      [failedRow({ operation: "push", host: "github.com", error: "INVALID_GIT_CONFIG" })],
    ]);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("the row carries the caller's attribution", async () => {
    const { log, injector } = recorder();
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "push", repository: "git@github.com:org/repo.git" },
          new Uint8Array(Buffer.from("not-a-key")),
          policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
          { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
          "secret-1",
          ATTRIBUTION,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expectAttributed(expectOneFailedUse(log, "INVALID_GIT_CONFIG"));
    expect(spawnMock).not.toHaveBeenCalled();
  });
});

describeGit("E-19, E-20: a repository git reads otherwise than the vault: one failed row", () => {
  const spawnMock = vi.mocked(spawnCaptured);
  const DASH_REPO = "--upload-pack=x@allowed.invalid:p";
  const allowed = () =>
    policy({ command_allowlist: [GIT as string], host_allowlist: ["allowed.invalid"] });
  const pinned: ConnectionConfig = {
    ssh: { known_hosts: ["allowed.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
  };
  let scratch: string;
  let key: string;

  beforeAll(() => {
    key = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    }).privateKey;
  });

  beforeEach(() => {
    scratch = mkdtempSync(join(tmpdir(), "harpoc-git-audit-dash-"));
    spawnMock.mockReset();
    spawnMock.mockImplementation((_cmd, args) => {
      const sub = gitSubcommand(args);
      const stdout =
        sub === "rev-parse"
          ? `${join(scratch, ".git", "objects")}\n${join(scratch, ".git", "shallow")}\nsha1\n`
          : sub === "symbolic-ref"
            ? "refs/heads/main\n"
            : sub === "config"
              ? "remote.origin.url\0"
              : "";
      return Promise.resolve({ ...OK_RESULT, stdout });
    });
  });

  afterEach(() => {
    rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it.each(["clone", "pull", "push", "fetch", "ls-remote"])(
    "%s with `-o` before the vault's `--`: refused with one row, nothing spawned",
    async (operation) => {
      const { log, injector } = recorder();
      const tree =
        operation === "clone" || operation === "ls-remote" ? {} : { working_directory: scratch };
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            unparsed(operation, { repository: DASH_REPO, args: ["-o"], ...tree }),
            new Uint8Array(Buffer.from(key)),
            allowed(),
            pinned,
            "secret-1",
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe("repository must not start with '-'");
      expect(log.mock.calls).toEqual([[failedRow({ operation, error: "INVALID_GIT_CONFIG" })]]);
      expect(spawnMock.mock.calls.length).toBe(0);
    },
  );

  it("ls-remote of a repository whose dash follows leading whitespace: refused with one row, nothing spawned", async () => {
    const { log, injector } = recorder();
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          unparsed("ls-remote", { repository: ` ${DASH_REPO}`, args: ["-o"] }),
          new Uint8Array(Buffer.from(key)),
          allowed(),
          pinned,
          "secret-1",
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe("repository must not start with '-'");
    expect(log.mock.calls).toEqual([
      [failedRow({ operation: "ls-remote", error: "INVALID_GIT_CONFIG" })],
    ]);
    expect(spawnMock.mock.calls.length).toBe(0);
  });

  it("an scp-form repository whose user part holds a colon is no SSH repository: the unsupported-transport row, no host, nothing spawned (E-20)", async () => {
    const { log, injector } = recorder();
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          unparsed("ls-remote", { repository: "evil.invalid:x@allowed.invalid:p" }),
          new Uint8Array(Buffer.from(key)),
          allowed(),
          pinned,
          "secret-1",
        ),
      ErrorCode.GIT_UNSUPPORTED_TRANSPORT,
    );
    expect(log.mock.calls).toEqual([
      [failedRow({ operation: "ls-remote", error: "GIT_UNSUPPORTED_TRANSPORT" })],
    ]);
    expect(spawnMock.mock.calls.length).toBe(0);
  });
});
