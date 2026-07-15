import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

const GIT = resolveExecutable("git", controlledPathDirs());
const SSH = resolveExecutable("ssh", controlledPathDirs());
const describeGit = GIT ? describe : describe.skip;
const describeGitSsh = GIT && SSH ? describe : describe.skip;

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
};

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    ...overrides,
  };
}

type SpawnCall = [string, string[], { env: Record<string, string>; redact?: string[] }];

// Positive-path assertions on the spawned git command (code review 2026-07-07,
// M13): the credential must reach git via the vault-authored GIT_ASKPASS helper
// through the child environment — never argv — and the SSH transport must carry
// the hardening args in GIT_SSH_COMMAND.
describeGit("GitInjector HTTPS credential handling (git resolvable)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("passes the credential via GIT_ASKPASS env vars, never argv", async () => {
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "https://8.8.8.8/org/repo.git",
    };
    const result = await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({
        command_allowlist: [GIT as string],
        url_allowlist: ["https://8.8.8.8/*"],
      }),
      undefined,
    );

    expect(result.exit_code).toBe(0);
    expect(spawnMock).toHaveBeenCalledOnce();
    const [command, args, opts] = spawnMock.mock.calls[0] as SpawnCall;

    expect(command).toBe(GIT);
    expect(args).toEqual(["clone", "https://8.8.8.8/org/repo.git"]);

    expect(opts.env.GIT_ASKPASS).toBeTruthy();
    expect(opts.env.HARPOC_GIT_USERNAME).toBe("git-user");
    expect(opts.env.HARPOC_GIT_PASSWORD).toBe("s3cret-token-value");
    expect(opts.env.GIT_TERMINAL_PROMPT).toBe("0");

    // The credential appears in no argv element in any form.
    expect(args.every((a) => !a.includes("s3cret-token-value") && !a.includes("git-user"))).toBe(
      true,
    );
    // Both credential halves are redacted from any captured output.
    expect(opts.redact).toContain("s3cret-token-value");
    expect(opts.redact).toContain("git-user");
  });

  it("skips a 1-2 char username in the redaction set (would shred output)", async () => {
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "https://8.8.8.8/org/repo.git",
    };
    await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("ab:s3cret-token-value")),
      policy({
        command_allowlist: [GIT as string],
        url_allowlist: ["https://8.8.8.8/*"],
      }),
      undefined,
    );

    const [, , opts] = vi.mocked(spawnCaptured).mock.calls[0] as SpawnCall;
    expect(opts.redact).toContain("s3cret-token-value");
    expect(opts.redact).not.toContain("ab");
  });
});

describeGitSsh("GitInjector SSH transport hardening (git + ssh resolvable)", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("wires GIT_SSH_COMMAND with the hardening args and the agent socket", async () => {
    const { privateKey: keyPem } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
    };
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "git@github.com:org/repo.git",
    };

    const result = await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from(keyPem)),
      policy({
        command_allowlist: [GIT as string],
        host_allowlist: ["github.com"],
      }),
      config,
    );

    expect(result.exit_code).toBe(0);
    expect(spawnMock).toHaveBeenCalledOnce();
    const [command, args, opts] = spawnMock.mock.calls[0] as SpawnCall;

    expect(command).toBe(GIT);
    expect(args).toEqual(["clone", "git@github.com:org/repo.git"]);

    const sshCommand = opts.env.GIT_SSH_COMMAND ?? "";
    expect(sshCommand).toContain("StrictHostKeyChecking=yes");
    expect(sshCommand).toContain("BatchMode=yes");
    expect(sshCommand).toContain("UserKnownHostsFile=");
    expect(sshCommand).toContain("IdentitiesOnly=yes");
    expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
    expect(opts.env.GIT_TERMINAL_PROMPT).toBe("0");

    // The private key reaches ssh only through the ephemeral agent socket.
    expect(args.every((a) => !a.includes("PRIVATE KEY"))).toBe(true);
    expect(Object.values(opts.env).every((v) => !v.includes("PRIVATE KEY"))).toBe(true);
    expect(opts.redact).toContain(keyPem);
  });
});

describeGit("GitInjector network isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const cloneAction: GitAction = {
    type: "git",
    operation: "clone",
    repository: "https://8.8.8.8/org/repo.git",
  };

  const isolatedPolicy = () =>
    policy({
      command_allowlist: [GIT as string],
      url_allowlist: ["https://8.8.8.8/*"],
      network_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, isolation_mechanism: "unshare" });
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      isolatedPolicy(),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          transport: "https",
          network_isolation: true,
          isolation_mechanism: "unshare",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        cloneAction,
        new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
        isolatedPolicy(),
        undefined,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits network_isolation: false", async () => {
    const log = vi.fn();
    const audited = new GitInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      cloneAction,
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy({ command_allowlist: [GIT as string], url_allowlist: ["https://8.8.8.8/*"] }),
      undefined,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ network_isolation: false }),
      }),
    );
  });
});
