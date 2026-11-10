/**
 * E-24: for a git-over-SSH use the host the allowlist judges and the audit row
 * names is the host the vault's ssh dials. `-o HostName=<judged host>` leads
 * GIT_SSH_COMMAND on every credential-bearing step, so the destination git
 * derives from the address by its own rules names the user and the port at most; a judged
 * host ssh would not read back as itself is refused before any spawn, with
 * one failed row that never carries it. Blocks 1 and 2 mock the spawn seam;
 * block 3 runs real git against a stand-in `ssh` that asks the real client
 * what it would dial (`ssh -G`: no connection, no lookup).
 */
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
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

// The injector resolves ssh for GIT_SSH_COMMAND against the process PATH; on
// Windows only the native Win32-OpenSSH client is accepted, so its directory
// leads the PATH (as in git-injector.spawn.test.ts).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveNativeSshClient("ssh");
// Skipped where git does not resolve (the command allowlist resolves it before the SSH
// transport is entered); blocks 2 and 3 also need the native ssh client to resolve.
const describeGit = describe.skipIf(GIT === null);
const describeGitSsh = describe.skipIf(GIT === null || SSH === null);
// A script cannot stand in for ssh.exe (the resolver takes `.exe` / `.com` alone on win32), so
// the real-git rows run on the POSIX legs and in the dev container.
const describeGitSshPosix = describe.skipIf(
  GIT === null || SSH === null || process.platform === "win32",
);

const OPERATIONS = ["clone", "pull", "push", "fetch", "ls-remote"] as const;
const NULL_GIT_CONFIG = process.platform === "win32" ? "NUL" : "/dev/null";

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

type SpawnCall = [string, string[], { env: Record<string, string>; cwd?: string }];

function gitSubcommand(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "-c") i++;
    else if (!a.startsWith("-")) return a;
  }
  return undefined;
}

function policy(hosts: string[]): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: hosts,
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
  };
}

/** The action as an unparsed caller hands it to the injector (git-injector.audit.test.ts). */
function unparsed(operation: string, patch: Record<string, unknown>): GitAction {
  return { type: "git", operation, ...patch } as unknown as GitAction;
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

const PINNED: ConnectionConfig = {
  ssh: { known_hosts: ["allowed.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};

// Every entry admits the judged host of a row below, so a row whose check went missing reaches
// the allowlist's "yes" — and then the spawn seam — instead of HOST_NOT_ALLOWED.
const ADMITTING = ["allowed.invalid", "*.allowed.invalid", "*.invalid", "[::1]", "127.0.0.1"];

// The judged host of each: `b@x.invalid`, `evil.invalid%2f.allowed.invalid`, `%h.allowed.invalid`,
// `evil.invalid #.allowed.invalid`, `evil.invalid<LF>.allowed.invalid`, `"evil.invalid".allowed.invalid`,
// `-oProxyCommand=x.allowed.invalid`, `-x.allowed.invalid`, `b<u-umlaut>cher.allowed.invalid`, `[`,
// `[127.0.0.1]`, a name of 256 characters.
const NOT_A_HOST: ReadonlyArray<readonly [string, string]> = [
  ["an @ in the scp host part", "a@b@x.invalid:path"],
  ["a percent-encoded octet in the URL host", "ssh://evil.invalid%2f.allowed.invalid/p"],
  ["a HostName token in the URL host", "ssh://%h.allowed.invalid/p"],
  ["a space and a # in the scp host part", "git@evil.invalid #.allowed.invalid:x@[ok.invalid]:z"],
  ["a line feed in the scp host part", "git@evil.invalid\n.allowed.invalid:p"],
  ["a quote in the scp host part", 'git@"evil.invalid".allowed.invalid:p'],
  ["a leading dash in the URL host", "ssh://git@-oProxyCommand=x.allowed.invalid/p"],
  ["a leading dash in the scp host part", "git@-x.allowed.invalid:p"],
  ["a host name outside ASCII", "git@bücher.allowed.invalid:p"],
  ["a bracket where the scp host stands", "git@[::1]:p"],
  ["a bracketed IPv4 literal where the scp host stands", "git@[127.0.0.1]:p"],
  ["a host name of 256 characters", `git@${"a".repeat(240)}.allowed.invalid:p`],
];

describeGit("E-24: a judged host ssh would not read back as itself is refused", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  describe.each(NOT_A_HOST)("%s", (_label, repository) => {
    it.each(OPERATIONS)(
      "%s: INVALID_GIT_CONFIG, one row without a host, nothing spawned",
      async (operation) => {
        const { log, injector } = recorder();
        const err = await expectVaultError(
          () =>
            injector.executeWithSecret(
              unparsed(operation, { repository }),
              new Uint8Array(Buffer.from("not-a-key")),
              policy(ADMITTING),
              PINNED,
              "secret-1",
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(
          "SSH host of the repository must be a host name or an IPv6 literal",
        );
        expect(log.mock.calls).toEqual([[failedRow({ operation, error: "INVALID_GIT_CONFIG" })]]);
        expect(spawnMock.mock.calls.length).toBe(0);
      },
    );
  });

  // 255 characters is a host: it passes the check and meets the missing known-host pin.
  it("control: a host name of 255 characters reaches the known-host pin", async () => {
    const { log, injector } = recorder();
    const host = `${"a".repeat(239)}.allowed.invalid`;
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          unparsed("ls-remote", { repository: `git@${host}:p` }),
          new Uint8Array(Buffer.from("not-a-key")),
          policy(ADMITTING),
          undefined,
          "secret-1",
        ),
      ErrorCode.SSH_NOT_CONFIGURED,
    );
    expect(log.mock.calls).toEqual([
      [failedRow({ operation: "ls-remote", host, error: "SSH_NOT_CONFIGURED" })],
    ]);
  });

  // The check stands before the allowlist: a host that is none is never written into a row.
  it("control: with an allowlist that admits nothing the refusal is the same row", async () => {
    const { log, injector } = recorder();
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          unparsed("ls-remote", { repository: "a@b@x.invalid:path" }),
          new Uint8Array(Buffer.from("not-a-key")),
          policy([]),
          PINNED,
          "secret-1",
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(log.mock.calls).toEqual([
      [failedRow({ operation: "ls-remote", error: "INVALID_GIT_CONFIG" })],
    ]);
  });
});

// Addresses git reads otherwise than the vault (measured on git 2.39.5 and 2.51.0, research-host.md
// appendix A; the last row on git 2.51.0, where git hands ssh the word
// `ssh://x@evil.invalid:2222`): the vault judges `allowed.invalid`; git hands ssh a destination
// whose host is `evil.invalid`, `fd00::1` or `allow<TAB>ed.invalid`.
const READ_OTHERWISE: ReadonlyArray<readonly [string, string]> = [
  ["git's bracket rule behind an scp path", "git@allowed.invalid:x@[evil.invalid]:z"],
  ["a bracketed scp address holding a second @", "[git@allowed.invalid:x@evil.invalid]:z"],
  ["@[ deeper in an scp path", "git@allowed.invalid:p/@[evil.invalid]/q:r"],
  ["a percent-encoded / in the URL userinfo", "ssh://evil.invalid%2F@allowed.invalid/p"],
  [
    "a percent-encoded port and / in the URL userinfo",
    "ssh://evil.invalid%3A2222%2F@allowed.invalid/p",
  ],
  ["a # in the URL authority", "ssh://allowed.invalid#@evil.invalid/p"],
  ["a ? in the URL authority", "ssh://allowed.invalid?@evil.invalid/p"],
  ["a bracketed URL userinfo", "ssh://[evil.invalid]@allowed.invalid/p"],
  ["a bracketed URL userinfo with a port", "ssh://[evil.invalid:2222]@allowed.invalid/p"],
  ["an IPv6 literal as the URL userinfo", "ssh://[fd00::1]@allowed.invalid/p"],
  ["@[ in the URL path", "ssh://git@allowed.invalid/x@[evil.invalid]/p"],
  ["@[ in the URL path with a port", "ssh://allowed.invalid/@[evil.invalid]:2222/p"],
  ["a percent-encoded @[ in the URL path", "ssh://git@allowed.invalid/x%40%5Bevil.invalid%5D/p"],
  [
    "a percent-encoded :// in a bracketed URL userinfo",
    "ssh://ssh%3A%2F%2Fx@[evil.invalid:2222]@allowed.invalid/p",
  ],
];

// The URL parser drops the tab and the vault judges `allowed.invalid`; git hands ssh
// `git@allow<TAB>ed.invalid`, which every measured client refuses to dial (`hostname contains
// invalid characters`) — so it has a row in block 2 and none in block 3.
const DROPPED_TAB: readonly [string, string] = [
  "a tab the URL parser drops",
  "ssh://git@allow\ted.invalid/p",
];

// [repository, the HostName value, the row's host]
const LEGITIMATE: ReadonlyArray<readonly [string, string, string]> = [
  ["git@allowed.invalid:org/repo.git", "allowed.invalid", "allowed.invalid"],
  ["user.name@allowed.invalid:path", "allowed.invalid", "allowed.invalid"],
  ["[git@allowed.invalid:2222]:org/repo.git", "allowed.invalid", "allowed.invalid"],
  ["ssh://git@allowed.invalid/org/repo.git", "allowed.invalid", "allowed.invalid"],
  ["ssh://git@allowed.invalid:2222/org/repo.git", "allowed.invalid", "allowed.invalid"],
  ["ssh://allowed.invalid/~git/repo.git", "allowed.invalid", "allowed.invalid"],
  ["ssh://us%65r@allowed.invalid/p%20q/r.git", "allowed.invalid", "allowed.invalid"],
  ["ssh://a%40b@allowed.invalid/p", "allowed.invalid", "allowed.invalid"],
  ["ssh://git@ALLOWED.INVALID/p", "ALLOWED.INVALID", "ALLOWED.INVALID"],
  ["git@sub_host.allowed.invalid:p", "sub_host.allowed.invalid", "sub_host.allowed.invalid"],
  [
    "git@xn--bcher-kva.allowed.invalid:p",
    "xn--bcher-kva.allowed.invalid",
    "xn--bcher-kva.allowed.invalid",
  ],
  ["ssh://git@127.0.0.1:2222/p", "127.0.0.1", "127.0.0.1"],
  ["ssh://git@[::1]:2222/p", "::1", "[::1]"],
];

const NETWORK_STEPS: Record<(typeof OPERATIONS)[number], number> = {
  clone: 2,
  pull: 1,
  push: 1,
  fetch: 1,
  "ls-remote": 1,
};

describeGitSsh(
  "E-24: `-o HostName=<judged host>` leads GIT_SSH_COMMAND on every credential-bearing step",
  () => {
    const spawnMock = vi.mocked(spawnCaptured);
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
      scratch = mkdtempSync(join(tmpdir(), "harpoc-git-ssh-host-"));
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

    async function expectDialed(
      operation: (typeof OPERATIONS)[number],
      repository: string,
      hostName: string,
      rowHost: string,
    ): Promise<void> {
      const { log, injector } = recorder();
      const tree =
        operation === "clone" || operation === "ls-remote" ? {} : { working_directory: scratch };
      await injector.executeWithSecret(
        unparsed(operation, { repository, ...tree }),
        new Uint8Array(Buffer.from(key)),
        policy(ADMITTING),
        PINNED,
        "secret-1",
      );
      const network = (spawnMock.mock.calls as SpawnCall[]).filter(
        ([, , opts]) => "GIT_SSH_COMMAND" in opts.env,
      );
      expect(network.length).toBe(NETWORK_STEPS[operation]);
      for (const [, args, opts] of network) {
        const command = opts.env.GIT_SSH_COMMAND as string;
        // The pair is the command's first option and its only HostName.
        expect(command.indexOf(" -o ")).toBe(command.indexOf(` -o HostName=${hostName} -F none `));
        expect(command.indexOf(" -o ") > 0).toBe(true);
        expect(command.split("HostName=").length).toBe(2);
        // git still receives the address as the caller wrote it, behind `--`.
        expect(args[args.indexOf("--") + 1]).toBe(repository);
      }
      const rows = log.mock.calls.map((c) => c[0] as AuditLogOptions);
      expect(rows.length).toBe(1);
      expect(rows[0]?.success).toBe(true);
      expect(rows[0]?.detail?.transport).toBe("ssh");
      expect(rows[0]?.detail?.host).toBe(rowHost);
    }

    describe.each([...READ_OTHERWISE, DROPPED_TAB])("%s", (_label, repository) => {
      it.each(OPERATIONS)("%s: the vault's ssh is told to dial the judged host", (operation) =>
        expectDialed(operation, repository, "allowed.invalid", "allowed.invalid"),
      );
    });

    describe.each(LEGITIMATE)("control: %s", (repository, hostName, rowHost) => {
      it.each(OPERATIONS)("%s: HostName is the address's own host", (operation) =>
        expectDialed(operation, repository, hostName, rowHost),
      );
    });
  },
);

describeGitSshPosix(
  "E-24: real git and a stand-in ssh — the host the real client would dial is the judged host",
  () => {
    const spawnMock = vi.mocked(spawnCaptured);
    const savedPath = process.env.PATH;
    let scratch: string;
    let out: string;
    let key: string;

    beforeAll(() => {
      key = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs1", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      }).privateKey;
    });

    beforeEach(() => {
      scratch = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-git-ssh-host-real-")));
      out = join(scratch, "dial.out");
      const standIn = join(scratch, "bin", "ssh");
      mkdirSync(join(scratch, "bin"));
      // The stand-in asks the real client for its effective configuration and fails the step.
      writeFileSync(standIn, `#!/bin/sh\n'${SSH as string}' -G "$@" > '${out}' 2>&1\nexit 1\n`);
      chmodSync(standIn, 0o755);
      process.env.PATH = `${join(scratch, "bin")}${delimiter}${dirname(GIT as string)}`;
      spawnMock.mockReset();
      spawnMock.mockImplementation(realSpawnCaptured);
    });

    afterEach(() => {
      process.env.PATH = savedPath;
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    const env = () => ({
      ...process.env,
      PATH: savedPath,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG,
    });

    /** A tree with one commit whose `origin` is the repository (a fetch looks its remote up by URL). */
    function tree(repository: string): string {
      const wd = join(scratch, "wd");
      execFileSync(GIT as string, ["init", "-q", wd], {
        env: env(),
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 20_000,
      });
      execFileSync(
        GIT as string,
        [
          "-c",
          "user.name=t",
          "-c",
          "user.email=t@t.invalid",
          "commit",
          "-q",
          "--allow-empty",
          "-m",
          "c",
        ],
        { cwd: wd, env: env(), stdio: ["ignore", "pipe", "pipe"], timeout: 20_000 },
      );
      execFileSync(GIT as string, ["config", "remote.origin.url", repository], {
        cwd: wd,
        env: env(),
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 20_000,
      });
      return wd;
    }

    async function expectSshDials(
      operation: (typeof OPERATIONS)[number],
      repository: string,
      hostname: string,
      rowHost: string,
    ): Promise<void> {
      const { log, injector } = recorder();
      const where =
        operation === "clone" || operation === "ls-remote"
          ? {}
          : { working_directory: tree(repository) };
      const result = await injector.executeWithSecret(
        unparsed(operation, { repository, ...where }),
        new Uint8Array(Buffer.from(key)),
        policy(ADMITTING),
        PINNED,
        "secret-1",
      );
      expect(result.exit_code === 0).toBe(false);
      const hostnames = readFileSync(out, "utf8")
        .split("\n")
        .filter((line) => line.startsWith("hostname "));
      expect(hostnames).toEqual([`hostname ${hostname}`]);
      const rows = log.mock.calls.map((c) => c[0] as AuditLogOptions);
      expect(rows.length).toBe(1);
      expect(rows[0]?.detail?.host).toBe(rowHost);
    }

    describe.each(READ_OTHERWISE)("%s", (_label, repository) => {
      it.each(OPERATIONS)("%s: ssh -G reports hostname allowed.invalid", (operation) =>
        expectSshDials(operation, repository, "allowed.invalid", "allowed.invalid"),
      );
    });

    describe("control: ssh://git@[::1]:2222/p", () => {
      it.each(OPERATIONS)("%s: ssh -G reports hostname ::1", (operation) =>
        expectSshDials(operation, "ssh://git@[::1]:2222/p", "::1", "[::1]"),
      );
    });
  },
);
