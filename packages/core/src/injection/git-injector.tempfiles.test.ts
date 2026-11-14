import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";
import type { Mock } from "vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, GitOperation, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { agentSocketAccepts } from "./__fixtures__/agent-socket.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    mkdtempSync: vi.fn(actual.mkdtempSync),
    rmSync: vi.fn(actual.rmSync),
    writeFileSync: vi.fn(actual.writeFileSync),
  };
});

const {
  mkdtempSync: realMkdtempSync,
  rmSync: realRmSync,
  writeFileSync: realWriteFileSync,
} = await vi.importActual<typeof import("node:fs")>("node:fs");

if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");
// Skipped where git (and, for the SSH transport, the native ssh client) does not resolve.
const describeGit = describe.skipIf(GIT === null);
const describeGitSsh = describe.skipIf(GIT === null || SSH === null);
// POSIX only besides: on win32 the agent serves a named pipe and creates no socket directory.
const describeGitSshPosix = describe.skipIf(
  GIT === null || SSH === null || process.platform === "win32",
);

function overrideTempEnv(dir: string): { TMPDIR?: string; TMP?: string; TEMP?: string } {
  const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = dir;
  process.env.TMP = dir;
  process.env.TEMP = dir;
  return saved;
}

function restoreTempEnv(saved: { TMPDIR?: string; TMP?: string; TEMP?: string }): void {
  if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = saved.TMPDIR;
  if (saved.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = saved.TMP;
  if (saved.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = saved.TEMP;
}

function ioError(code: string, path?: string): NodeJS.ErrnoException {
  const err = new Error(
    path === undefined ? `${code}: injected` : `${code}: injected, '${path}'`,
  ) as NodeJS.ErrnoException;
  err.code = code;
  if (path !== undefined) err.path = path;
  return err;
}

function failMkdtemp(failing: (prefix: string) => boolean, code: string): void {
  vi.mocked(mkdtempSync).mockImplementation((prefix, options) => {
    if (failing(prefix)) throw ioError(code, `${prefix}XXXXXX`);
    return realMkdtempSync(prefix, options);
  });
}

function failWrite(failing: (path: string) => boolean, code: string): void {
  vi.mocked(writeFileSync).mockImplementation((file, data, options) => {
    if (failing(String(file))) throw ioError(code, String(file));
    realWriteFileSync(file, data, options);
  });
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

function httpsPolicy(): InjectionPolicy {
  return policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] });
}

const SECRET_ID = "secret-1";
const SSH_CONFIG: ConnectionConfig = {
  ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};
const TEMP_FILE_UNPREPARED = "a temporary file of the git context could not be prepared";
const RELAY_UNPREPARED = "the relay repository could not be prepared";
const AGENT_DIR_UNCREATED =
  "Ephemeral ssh-agent failed: the agent's socket directory could not be created";

let tempRoot: string;
let saved: { TMPDIR?: string; TMP?: string; TEMP?: string };
let log: Mock;

// The short prefix keeps the agent's socket inside darwin's 104-byte sun_path under its long $TMPDIR.
beforeEach(() => {
  tempRoot = mkdtempSync(join(tmpdir(), "harpoc-git-tf-"));
  saved = overrideTempEnv(tempRoot);
  vi.mocked(spawnCaptured).mockReset();
  log = vi.fn();
});

afterEach(() => {
  restoreTempEnv(saved);
  vi.mocked(writeFileSync).mockReset();
  vi.mocked(mkdtempSync).mockReset();
  vi.mocked(rmSync).mockReset();
  rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function auditedInjector(): GitInjector {
  return new GitInjector({ log } as unknown as AuditLogger);
}

function useHttps(operation: GitOperation = "clone", config?: ConnectionConfig): Promise<unknown> {
  return auditedInjector().executeWithSecret(
    { type: "git", operation, repository: "https://8.8.8.8/org/repo.git" },
    new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
    httpsPolicy(),
    config,
    SECRET_ID,
  );
}

function useSsh(keyPem: string): Promise<unknown> {
  return auditedInjector().executeWithSecret(
    { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
    new Uint8Array(Buffer.from(keyPem)),
    policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
    SSH_CONFIG,
    SECRET_ID,
  );
}

function rsaKeyPem(): string {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }).privateKey;
}

async function expectCodedFailure(
  run: () => Promise<unknown>,
  message: string,
  detail: Record<string, unknown>,
): Promise<void> {
  await expectCodedRow(run, message, detail);
  expect(readdirSync(tempRoot)).toEqual([]);
}

async function expectCodedRow(
  run: () => Promise<unknown>,
  message: string,
  detail: Record<string, unknown>,
): Promise<void> {
  await expectFailedRow(
    run,
    ErrorCode.GIT_OPERATION_FAILED,
    `Git operation failed: ${message}`,
    detail,
  );
}

async function expectAgentFailedRow(
  run: () => Promise<unknown>,
  detail: Record<string, unknown>,
): Promise<void> {
  await expectFailedRow(run, ErrorCode.SSH_AGENT_FAILED, AGENT_DIR_UNCREATED, detail);
}

/** `run` fails with the code and fixed message, names no temp path and writes one failed row. */
async function expectFailedRow(
  run: () => Promise<unknown>,
  code: ErrorCode,
  fullMessage: string,
  detail: Record<string, unknown>,
): Promise<void> {
  const err = await expectVaultError(run, code);
  expect(err.message.includes(tempRoot)).toBe(false);
  expect(err.message === fullMessage).toBe(true);
  expect(log.mock.calls).toEqual([
    [
      {
        eventType: "secret.use",
        secretId: SECRET_ID,
        detail: { context: "git", ...detail },
        success: false,
      },
    ],
  ]);
}

function postPlanRow(operation: GitOperation): Record<string, unknown> {
  return {
    operation,
    transport: "https",
    error: "GIT_OPERATION_FAILED",
    network_isolation: false,
    fs_isolation: false,
  };
}

describeGit("the relay's temporary directory cannot be created", () => {
  it("ends a clone GIT_OPERATION_FAILED with one post-plan row, nothing spawned and no directory left", async () => {
    failMkdtemp((prefix) => basename(prefix) === "harpoc-git-relay-", "ENOSPC");
    await expectCodedFailure(() => useHttps("clone"), RELAY_UNPREPARED, postPlanRow("clone"));
    expect(spawnCaptured).not.toHaveBeenCalled();
  });

  it("ends an ls-remote GIT_OPERATION_FAILED with one post-plan row, nothing spawned and no directory left", async () => {
    failMkdtemp((prefix) => basename(prefix) === "harpoc-git-relay-", "ENOSPC");
    await expectCodedFailure(
      () => useHttps("ls-remote"),
      RELAY_UNPREPARED,
      postPlanRow("ls-remote"),
    );
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGit("the hooks directory cannot be created (HTTPS)", () => {
  it("ends GIT_OPERATION_FAILED with one failed row, nothing spawned and no directory left", async () => {
    failMkdtemp((prefix) => basename(prefix) === "harpoc-git-hooks-", "ENOSPC");
    await expectCodedFailure(() => useHttps(), TEMP_FILE_UNPREPARED, {
      operation: "clone",
      error: "GIT_OPERATION_FAILED",
    });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGitSsh("the hooks directory cannot be created (SSH)", () => {
  it("ends GIT_OPERATION_FAILED with one failed row naming the host, nothing spawned and no directory left", async () => {
    failMkdtemp((prefix) => basename(prefix) === "harpoc-git-hooks-", "EACCES");
    await expectCodedFailure(() => useSsh("unused"), TEMP_FILE_UNPREPARED, {
      operation: "clone",
      host: "github.com",
      error: "GIT_OPERATION_FAILED",
    });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGit("the askpass directory cannot be created (HTTPS)", () => {
  it("ends GIT_OPERATION_FAILED with one failed row, nothing spawned and no directory left", async () => {
    failMkdtemp((prefix) => basename(prefix) === "harpoc-git-", "ENOSPC");
    await expectCodedFailure(() => useHttps(), TEMP_FILE_UNPREPARED, {
      operation: "clone",
      error: "GIT_OPERATION_FAILED",
    });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGit("the CA pin's temporary file cannot be created (HTTPS)", () => {
  it("ends GIT_OPERATION_FAILED with one failed row, nothing spawned and no directory left", async () => {
    failMkdtemp((prefix) => basename(prefix) === "harpoc-git-ca-", "ENOSPC");
    await expectCodedFailure(
      () => useHttps("clone", { git: { ca_pem: "unused-ca-pem" } }),
      TEMP_FILE_UNPREPARED,
      { operation: "clone", error: "GIT_OPERATION_FAILED" },
    );
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGit("a clone's rewrite of the relay HEAD fails (HTTPS)", () => {
  it("ends GIT_OPERATION_FAILED after the listing with one post-plan row and no relay left", async () => {
    vi.mocked(spawnCaptured).mockResolvedValue({
      exit_code: 0,
      stdout: `ref: refs/heads/main\tHEAD\n${"a".repeat(40)}\tHEAD\n`,
      stderr: "",
      timed_out: false,
      truncated: false,
      signal: null,
      spawn_failed: false,
      redacted: false,
    });
    failWrite(
      (path) =>
        basename(path) === "HEAD" &&
        basename(dirname(path)).startsWith("harpoc-git-relay-") &&
        vi.mocked(spawnCaptured).mock.calls.length > 0,
      "ENOSPC",
    );
    await expectCodedFailure(() => useHttps("clone"), RELAY_UNPREPARED, postPlanRow("clone"));
    expect(vi.mocked(spawnCaptured).mock.calls.map(([, args]) => gitSubcommand(args))).toEqual([
      "ls-remote",
    ]);
  });
});

describeGitSsh("the identity file cannot be written (SSH)", () => {
  it("ends GIT_OPERATION_FAILED with one failed row naming the host, nothing spawned and no directory left", async () => {
    failWrite((path) => basename(path) === "identity.pub", "EACCES");
    await expectCodedFailure(() => useSsh(rsaKeyPem()), TEMP_FILE_UNPREPARED, {
      operation: "clone",
      host: "github.com",
      error: "GIT_OPERATION_FAILED",
    });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGit("the askpass write fails (HTTPS)", () => {
  it("leaves no vault-authored directory behind and ends GIT_OPERATION_FAILED with one failed row", async () => {
    vi.mocked(writeFileSync).mockImplementationOnce((path) => {
      if (String(path).includes("askpass")) throw ioError("EACCES", String(path));
      throw new Error("unexpected first write");
    });
    await expectCodedFailure(() => useHttps(), TEMP_FILE_UNPREPARED, {
      operation: "clone",
      error: "GIT_OPERATION_FAILED",
    });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });

  it("ends GIT_OPERATION_FAILED with one failed row when its cleanup's removal fails too, nothing spawned", async () => {
    vi.mocked(writeFileSync).mockImplementationOnce((path) => {
      if (String(path).includes("askpass")) throw ioError("EACCES", String(path));
      throw new Error("unexpected first write");
    });
    let leftover: string | undefined;
    vi.mocked(rmSync).mockImplementationOnce((path) => {
      if (basename(String(path)).slice(0, -6) === "harpoc-git-") {
        leftover = String(path);
        throw ioError("EBUSY", leftover);
      }
      throw new Error("unexpected first removal");
    });
    // The failed cleanup leaves the askpass directory; the row removes it, on failure too.
    try {
      await expectCodedRow(() => useHttps(), TEMP_FILE_UNPREPARED, {
        operation: "clone",
        error: "GIT_OPERATION_FAILED",
      });
      expect(spawnCaptured).not.toHaveBeenCalled();
      expect(readdirSync(tempRoot).map((entry) => join(tempRoot, entry))).toEqual([leftover]);
    } finally {
      if (leftover !== undefined) {
        realRmSync(leftover, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    }
  });
});

describeGitSshPosix("the agent's socket directory cannot be created (SSH)", () => {
  it("ends SSH_AGENT_FAILED with one failed row naming the host, nothing spawned and no directory left", async () => {
    failMkdtemp((prefix) => basename(prefix) === "harpoc-agent-", "ENOSPC");
    await expectAgentFailedRow(() => useSsh(rsaKeyPem()), {
      operation: "clone",
      host: "github.com",
      error: "SSH_AGENT_FAILED",
    });
    expect(readdirSync(tempRoot)).toEqual([]);
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGitSsh("the known_hosts write fails (SSH)", () => {
  it("leaves no vault-authored directory behind and ends GIT_OPERATION_FAILED with one failed row naming the host", async () => {
    vi.mocked(writeFileSync).mockImplementationOnce((path) => {
      if (String(path).endsWith("known_hosts")) throw ioError("EACCES", String(path));
      throw new Error("unexpected first write");
    });
    await expectCodedFailure(() => useSsh(rsaKeyPem()), TEMP_FILE_UNPREPARED, {
      operation: "clone",
      host: "github.com",
      error: "GIT_OPERATION_FAILED",
    });
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGit("the argument build refuses (HTTPS)", () => {
  it("leaves no vault-authored directory behind and propagates the refusal", async () => {
    const injector = new GitInjector(null);
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "pull", repository: "https://8.8.8.8/org/repo.git" },
          new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
          httpsPolicy(),
          undefined,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(readdirSync(tempRoot)).toEqual([]);
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

describeGitSsh("the argument build refuses (SSH)", () => {
  it("leaves no vault-authored directory behind and propagates the refusal", async () => {
    const injector = new GitInjector(null);
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "pull", repository: "git@github.com:org/repo.git" },
          new Uint8Array(Buffer.from("unused")),
          policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
          { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(readdirSync(tempRoot)).toEqual([]);
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});

// I8: the agent's socket is serving at spawn and gone once the call settles.
describeGitSsh("the call completes (SSH)", () => {
  it("disposes the agent's socket and leaves no vault-authored directory behind", async () => {
    let sock = "";
    let servingAtSpawn = false;
    vi.mocked(spawnCaptured).mockImplementation(async (_cmd, _args, opts) => {
      // The clone's network steps carry the agent; its local step does not (F-1).
      if (opts.env.SSH_AUTH_SOCK !== undefined) {
        sock = opts.env.SSH_AUTH_SOCK;
        servingAtSpawn = await agentSocketAccepts(sock);
      }
      return {
        exit_code: 0,
        stdout: "",
        stderr: "",
        timed_out: false,
        truncated: false,
        signal: null,
        spawn_failed: false,
        redacted: false,
      };
    });
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const injector = new GitInjector(null);
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
      new Uint8Array(Buffer.from(keyPem)),
      policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
      { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
    );
    expect(servingAtSpawn).toBe(true);
    expect(await agentSocketAccepts(sock)).toBe(false);
    expect(readdirSync(tempRoot)).toEqual([]);
  });
});

describeGitSsh("the agent fails to start (SSH)", () => {
  it("leaves no vault-authored directory behind and propagates the refusal", async () => {
    const injector = new GitInjector(null);
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          { type: "git", operation: "clone", repository: "git@github.com:org/repo.git" },
          new Uint8Array(Buffer.from("not-a-valid-key")),
          policy({ command_allowlist: [GIT as string], host_allowlist: ["github.com"] }),
          { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
        ),
      ErrorCode.SSH_AGENT_FAILED,
    );
    expect(readdirSync(tempRoot)).toEqual([]);
    expect(spawnCaptured).not.toHaveBeenCalled();
  });
});
