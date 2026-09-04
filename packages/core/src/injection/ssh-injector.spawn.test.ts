import { generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SshAction } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { SshInjector } from "./ssh-injector.js";
import { system32Path } from "../win32-paths.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

// On Windows the ephemeral agent listens on a named pipe, which only the native
// Win32-OpenSSH client consumes through SSH_AUTH_SOCK; an MSYS build (the
// Git-bundled ssh a Git-Bash PATH resolves first) finds no agent and is refused
// before any spawn (D58). The ssh injector resolves the bare name against the process
// PATH itself, so the native directory has to lead there, not only in the allowlist
// entry this suite pins (ssh-live-auth.test.ts pins the same client for the same reason).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const SSH = resolveExecutable("ssh", controlledPathDirs());
const describeSsh = SSH ? describe : describe.skip;

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "deploy",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

function makeKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
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
    ...overrides,
  };
}

const ACTION: SshAction = {
  type: "ssh",
  host: "deploy.example.com",
  user: "deploy",
  command: "whoami",
};

const SSH_CONFIG: ConnectionConfig = {
  ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};

// Positive-path assertions on the spawned ssh command (code review 2026-07-07,
// M13): the hardening args, the agent-socket env and the key-redaction contract
// are load-bearing security behavior that the rejection tests never reach.
describeSsh("SshInjector spawn hardening (ssh resolvable)", () => {
  const injector = new SshInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("spawns ssh with strict host-key verification and batch-mode hardening", async () => {
    const keyPem = makeKeyPem();
    const result = await injector.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(keyPem)),
      policy({
        host_allowlist: ["deploy.example.com"],
        command_allowlist: [SSH as string],
      }),
      SSH_CONFIG,
    );

    expect(result.exit_code).toBe(0);
    expect(spawnMock).toHaveBeenCalledOnce();
    const [command, args, opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { env: Record<string, string>; redact?: string[] },
    ];

    expect(command).toBe(SSH);
    expect(args.join(" ")).toContain("-F none");
    expect(args).toContain("StrictHostKeyChecking=yes");
    expect(args).toContain("IdentitiesOnly=yes");
    expect(args).toContain("BatchMode=yes");
    expect(args).toContain("PasswordAuthentication=no");
    expect(args.some((a) => a.startsWith("UserKnownHostsFile="))).toBe(true);
    // The VALUE is double-quoted for ssh's readconf, which re-splits option
    // values on whitespace after argv: an unquoted path with a space (e.g. a
    // "C:/Users/Stefan G/…" temp dir) reads as two known_hosts files and strict
    // checking refuses a correctly pinned host.
    const khArg = args.find((a) => a.startsWith("UserKnownHostsFile=")) as string;
    expect(khArg).toMatch(/^UserKnownHostsFile="[^"]+known_hosts"$/);
    expect(args.some((a) => a.startsWith("ConnectTimeout="))).toBe(true);
    // IdentitiesOnly restricts ssh to file-backed identities, so the vault-written
    // .pub of the ephemeral key must ride along or the agent key is never offered.
    const iIdx = args.indexOf("-i");
    expect(iIdx).toBeGreaterThan(-1);
    expect(args[iIdx + 1]).toMatch(/identity\.pub$/);
    // "--" ends option parsing so the host positional can never read as a flag.
    expect(args.slice(-5)).toEqual(["-l", "deploy", "--", "deploy.example.com", "whoami"]);

    // The private key reaches ssh only through the ephemeral agent socket:
    expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
    expect(args.every((a) => !a.includes("PRIVATE KEY"))).toBe(true);
    expect(Object.values(opts.env).every((v) => !v.includes("PRIVATE KEY"))).toBe(true);
    // and it is redacted from any captured output.
    expect(opts.redact).toContain(keyPem);
  });

  it("passes a non-22 port as -p ahead of -l, leaving the positional tail intact", async () => {
    await injector.executeWithSecret(
      { ...ACTION, port: 2222 },
      new Uint8Array(Buffer.from(makeKeyPem())),
      policy({ host_allowlist: ["deploy.example.com"], command_allowlist: [SSH as string] }),
      SSH_CONFIG,
    );
    const [, args] = spawnMock.mock.calls[0] as [string, string[], { env: Record<string, string> }];
    expect(args.slice(-7)).toEqual([
      "-p",
      "2222",
      "-l",
      "deploy",
      "--",
      "deploy.example.com",
      "whoami",
    ]);
  });

  it("records the port in the secret.use detail when present", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    await audited.executeWithSecret(
      { ...ACTION, port: 2222 },
      new Uint8Array(Buffer.from(makeKeyPem())),
      policy({ host_allowlist: ["deploy.example.com"], command_allowlist: [SSH as string] }),
      SSH_CONFIG,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({ context: "ssh", host: "deploy.example.com", port: 2222 });
  });

  it("leaves the port out of the detail entirely when the action names none", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      policy({ host_allowlist: ["deploy.example.com"], command_allowlist: [SSH as string] }),
      SSH_CONFIG,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).not.toHaveProperty("port");
  });

  it("backs the agent identity with a vault-written .pub, removed after the invocation", async () => {
    let identityPath = "";
    let identityContentAtSpawn = "";
    spawnMock.mockImplementation((_cmd, args) => {
      identityPath = args[args.indexOf("-i") + 1] as string;
      identityContentAtSpawn = readFileSync(identityPath, "utf8");
      return Promise.resolve(OK_RESULT);
    });

    await injector.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      policy({
        host_allowlist: ["deploy.example.com"],
        command_allowlist: [SSH as string],
      }),
      SSH_CONFIG,
    );

    // At spawn time the file exists and holds exactly the public line —
    // never any private key material.
    expect(identityContentAtSpawn).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ harpoc-ephemeral\n$/);
    expect(identityContentAtSpawn).not.toContain("PRIVATE KEY");
    // The per-invocation temp file is gone once the call completes.
    expect(existsSync(identityPath)).toBe(false);
  });

  // T14: §4.5.3 layer 3 for the SSH context — the child gets a built
  // environment, never the vault process's own.
  it("spawns ssh with a built environment, not the vault's own", async () => {
    process.env.HARPOC_T14_SSH_AMBIENT = "ambient-value";
    process.env.HARPOC_T14_SSH_ALLOWED = "allowed-value";
    try {
      await injector.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        policy({
          host_allowlist: ["deploy.example.com"],
          command_allowlist: [SSH as string],
          env_allowlist: ["HARPOC_T14_SSH_ALLOWED"],
        }),
        SSH_CONFIG,
      );

      const [, , opts] = spawnMock.mock.calls[0] as [
        string,
        string[],
        { env: Record<string, string> },
      ];
      expect(opts.env.HARPOC_T14_SSH_AMBIENT).toBeUndefined();
      expect(opts.env.HARPOC_T14_SSH_ALLOWED).toBe("allowed-value");

      const expected = new Set([
        "PATH",
        "SystemRoot",
        "ProgramData",
        "SSH_AUTH_SOCK",
        "HARPOC_T14_SSH_ALLOWED",
      ]);
      expect(Object.keys(opts.env).filter((k) => !expected.has(k))).toEqual([]);
    } finally {
      delete process.env.HARPOC_T14_SSH_AMBIENT;
      delete process.env.HARPOC_T14_SSH_ALLOWED;
    }
  });

  it.runIf(process.platform === "win32")(
    "passes ProgramData through to ssh.exe (Win32-OpenSSH exits 255 silently without it)",
    async () => {
      await injector.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        policy({
          host_allowlist: ["deploy.example.com"],
          command_allowlist: [SSH as string],
        }),
        SSH_CONFIG,
      );
      const [, , opts] = spawnMock.mock.calls[0] as [
        string,
        string[],
        { env: Record<string, string> },
      ];
      expect(opts.env.ProgramData).toBe(process.env.ProgramData);
    },
  );
});

describeSsh("SshInjector network isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const isolatedPolicy = () =>
    policy({
      host_allowlist: ["deploy.example.com"],
      command_allowlist: [SSH as string],
      network_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, isolation_mechanism: "unshare" });
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      isolatedPolicy(),
      SSH_CONFIG,
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
          network_isolation: true,
          isolation_mechanism: "unshare",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        isolatedPolicy(),
        SSH_CONFIG,
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

  it("the host-key-mismatch denial carries the isolation posture (review fix F8)", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 255,
      stderr: "Host key verification failed.",
    });
    await expect(
      audited.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        isolatedPolicy(),
        SSH_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_HOST_KEY_MISMATCH });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: "SSH_HOST_KEY_MISMATCH",
          network_isolation: true,
        }),
      }),
    );
  });

  it("control: the host-key denial reports false under a non-isolating policy", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 255,
      stderr: "Host key verification failed.",
    });
    await expect(
      audited.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        policy({ host_allowlist: ["deploy.example.com"], command_allowlist: [SSH as string] }),
        SSH_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_HOST_KEY_MISMATCH });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: "SSH_HOST_KEY_MISMATCH",
          network_isolation: false,
        }),
      }),
    );
  });
});

describeSsh("SshInjector filesystem isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  const fsIsolatedPolicy = () =>
    policy({
      host_allowlist: ["deploy.example.com"],
      command_allowlist: [SSH as string],
      fs_isolation: true,
    });

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, fs_isolation_mechanism: "landlock" });
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      fsIsolatedPolicy(),
      SSH_CONFIG,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], { fsIsolation?: boolean }];
    expect(opts.fsIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          fs_isolation: true,
          fs_isolation_mechanism: "landlock",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.fsIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        fsIsolatedPolicy(),
        SSH_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.FS_ISOLATION_UNAVAILABLE,
          fs_isolation: true,
        }),
      }),
    );
  });

  it("the host-key-mismatch denial carries the filesystem-isolation posture", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 255,
      stderr: "Host key verification failed.",
    });
    await expect(
      audited.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        fsIsolatedPolicy(),
        SSH_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_HOST_KEY_MISMATCH });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: "SSH_HOST_KEY_MISMATCH",
          fs_isolation: true,
        }),
      }),
    );
  });

  it("defaults to an un-isolated spawn and audits fs_isolation: false", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      policy({ host_allowlist: ["deploy.example.com"], command_allowlist: [SSH as string] }),
      SSH_CONFIG,
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], { fsIsolation?: boolean }];
    expect(opts.fsIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ fs_isolation: false }),
      }),
    );
  });
});

describeSsh("SshInjector output sanitization on the row (Wave 2, E70)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("marks the audited result row sanitized when the spawn seam redacted output", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, redacted: true });
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      policy({ host_allowlist: ["deploy.example.com"], command_allowlist: [SSH as string] }),
      SSH_CONFIG,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect(row.detail).toMatchObject({ context: "ssh", sanitized: true });
  });

  it("leaves sanitized out of the row entirely when nothing was redacted", async () => {
    const log = vi.fn();
    const audited = new SshInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      policy({ host_allowlist: ["deploy.example.com"], command_allowlist: [SSH as string] }),
      SSH_CONFIG,
      "secret-1",
    );
    const row = log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> };
    expect("sanitized" in row.detail).toBe(false);
  });
});

describe.runIf(process.platform === "win32")(
  "SshInjector refuses an MSYS/Cygwin ssh client (D58)",
  () => {
    const spawnMock = vi.mocked(spawnCaptured);
    let fixtureDir: string;
    let stub: string;
    const savedPath = process.env.PATH;

    beforeEach(() => {
      spawnMock.mockReset();
      spawnMock.mockResolvedValue(OK_RESULT);
      fixtureDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-msys-ssh-")));
      stub = join(fixtureDir, "ssh.exe");
      writeFileSync(stub, "");
      writeFileSync(join(fixtureDir, "msys-2.0.dll"), "");
      process.env.PATH = fixtureDir;
    });

    afterEach(() => {
      process.env.PATH = savedPath;
      rmSync(fixtureDir, { recursive: true, force: true });
    });

    it("refuses before any spawn, with a failed secret.use row naming the code", async () => {
      const log = vi.fn();
      const injector = new SshInjector({ log } as unknown as AuditLogger);
      await expect(
        injector.executeWithSecret(
          ACTION,
          new Uint8Array(Buffer.from(makeKeyPem())),
          policy({
            host_allowlist: ["deploy.example.com"],
            command_allowlist: [stub],
          }),
          SSH_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.SSH_CLIENT_UNSUPPORTED });
      expect(spawnMock).not.toHaveBeenCalled();
      expect(log).toHaveBeenCalledTimes(1);
      expect(log.mock.calls[0]?.[0]).toMatchObject({
        eventType: "secret.use",
        success: false,
        detail: expect.objectContaining({ error: "SSH_CLIENT_UNSUPPORTED" }),
      });
    });

    it("guard-flip: without the DLL the same stub is spawned", async () => {
      rmSync(join(fixtureDir, "msys-2.0.dll"));
      const injector = new SshInjector(null);
      await injector.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        policy({
          host_allowlist: ["deploy.example.com"],
          command_allowlist: [stub],
        }),
        SSH_CONFIG,
      );
      expect(spawnMock).toHaveBeenCalledOnce();
      const [command] = spawnMock.mock.calls[0] as [string, string[], unknown];
      expect(command.toLowerCase()).toBe(stub.toLowerCase());
    });
  },
);
