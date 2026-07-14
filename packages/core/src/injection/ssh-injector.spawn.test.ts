import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SshAction } from "@harpoc/shared";
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
    // "--" ends option parsing so the host positional can never read as a flag.
    expect(args.slice(-5)).toEqual(["-l", "deploy", "--", "deploy.example.com", "whoami"]);

    // The private key reaches ssh only through the ephemeral agent socket:
    expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
    expect(args.every((a) => !a.includes("PRIVATE KEY"))).toBe(true);
    expect(Object.values(opts.env).every((v) => !v.includes("PRIVATE KEY"))).toBe(true);
    // and it is redacted from any captured output.
    expect(opts.redact).toContain(keyPem);
  });
});
