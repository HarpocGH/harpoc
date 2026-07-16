import { generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SshAction } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { SshInjector } from "./ssh-injector.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

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
