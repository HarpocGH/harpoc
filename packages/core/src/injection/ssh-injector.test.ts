import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SshAction } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { spawnCaptured } from "./spawn-captured.js";
import { SshInjector } from "./ssh-injector.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

function makeKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
}

const SECRET = new Uint8Array(Buffer.from(makeKeyPem()));

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

const ACTION: SshAction = {
  type: "ssh",
  host: "deploy.example.com",
  user: "deploy",
  command: "whoami",
};

const SSH_CONFIG: ConnectionConfig = {
  ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};

describe("SshInjector enforcement", () => {
  const injector = new SshInjector(null);

  it("denies by default when the host allowlist is empty (fail-safe)", async () => {
    await expect(
      injector.executeWithSecret(ACTION, SECRET, policy(), SSH_CONFIG),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
  });

  it("denies a host outside the allowlist", async () => {
    await expect(
      injector.executeWithSecret(
        ACTION,
        SECRET,
        policy({ host_allowlist: ["other.example.com"] }),
        SSH_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
  });

  it("requires pinned host keys (no TOFU)", async () => {
    await expect(
      injector.executeWithSecret(
        ACTION,
        SECRET,
        policy({ host_allowlist: ["deploy.example.com"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_NOT_CONFIGURED });
  });

  it("requires the ssh binary to be command-allowlisted (fail-safe deny)", async () => {
    await expect(
      injector.executeWithSecret(
        ACTION,
        SECRET,
        policy({ host_allowlist: ["deploy.example.com"] }),
        SSH_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });

  it("refuses a host starting with '-' before any other work (argv option smuggling)", async () => {
    await expect(
      injector.executeWithSecret(
        { ...ACTION, host: "-oProxyCommand.evil" },
        SECRET,
        policy({ host_allowlist: ["-oProxyCommand.evil"] }),
        SSH_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_SSH_CONFIG });
  });

  it("refuses a user starting with '-'", async () => {
    await expect(
      injector.executeWithSecret(
        { ...ACTION, user: "-l" },
        SECRET,
        policy({ host_allowlist: ["deploy.example.com"] }),
        SSH_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_SSH_CONFIG });
  });
});

const FIXED_MESSAGE = "host and user must be names of letters, digits, '.', '_' and '-'";
const DASH_MESSAGE = "host and user must not start with '-'";

const ATTRIBUTION: AuditAttribution = {
  principal_type: "agent",
  principal_id: "alice",
  session_id: "sess-attr-1",
  interface: "rest",
};

const NOT_A_NAME_HOSTS: ReadonlyArray<readonly [string, string]> = [
  ["an @ ahead of the allowlisted name", "evil.example@ok.example"],
  ["an ssh:// URI carrying a port", "ssh://evil.example:2222"],
  ["a :port suffix", "ok.example:2222"],
  ["a space", "ok example"],
  ["a %-token", "x%h.example"],
  ["an IPv6 literal with a zone id", "fe80::1%eth0"],
  ["a name outside ASCII", "ünï.example"],
  ["a /", "a/b.example"],
  ["brackets", "[ok.example]"],
  ["a #", "ok.example#x"],
];

const NOT_A_NAME_USERS: ReadonlyArray<readonly [string, string]> = [
  ["a %-token", "x%hy"],
  ["an environment expansion", "a$" + "{HOME}b"],
  ["a :", "u:x"],
  ["an @", "a@b"],
];

function recorder(): { log: Mock; injector: SshInjector } {
  const log = vi.fn();
  return { log, injector: new SshInjector({ log } as unknown as AuditLogger) };
}

function rowsOf(log: Mock): AuditLogOptions[] {
  return log.mock.calls.map((c) => c[0] as AuditLogOptions);
}

describe("a host or user outside the schema's charset is refused before the allowlist", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  async function expectRefused(action: SshAction, allowed: string, refused: string): Promise<void> {
    const { log, injector } = recorder();
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          action,
          SECRET,
          policy({ host_allowlist: [allowed] }),
          SSH_CONFIG,
          "secret-1",
        ),
      ErrorCode.INVALID_SSH_CONFIG,
    );
    expect(err.message.includes(refused)).toBe(false);
    expect(err.message === FIXED_MESSAGE).toBe(true);
    const rows = rowsOf(log);
    expect(rows.length).toBe(1);
    expect(rows[0]?.eventType).toBe("secret.use");
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail?.error).toBe("INVALID_SSH_CONFIG");
    expect(spawnMock.mock.calls.length).toBe(0);
  }

  it.each(NOT_A_NAME_HOSTS)(
    "a host with %s, admitted by the allowlist: INVALID_SSH_CONFIG, one failed row, nothing spawned",
    (_label, host) => expectRefused({ ...ACTION, host }, host, host),
  );

  it.each(NOT_A_NAME_USERS)(
    "a user with %s: INVALID_SSH_CONFIG, one failed row, nothing spawned",
    (_label, user) => expectRefused({ ...ACTION, user }, ACTION.host, user),
  );

  it("a host outside the charset that the allowlist does not admit: INVALID_SSH_CONFIG, not HOST_NOT_ALLOWED", () =>
    expectRefused({ ...ACTION, host: "ok.example:2222" }, ACTION.host, "ok.example:2222"));

  it("the row keeps the leading-dash refusal's shape: the same fields, the same values but the user", async () => {
    const run = async (user: string): Promise<{ message: string; rows: AuditLogOptions[] }> => {
      const { log, injector } = recorder();
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            { ...ACTION, port: 2222, user },
            SECRET,
            policy({ host_allowlist: [ACTION.host] }),
            SSH_CONFIG,
            "secret-1",
            ATTRIBUTION,
          ),
        ErrorCode.INVALID_SSH_CONFIG,
      );
      return { message: err.message, rows: rowsOf(log) };
    };
    const dash = await run("-l");
    const crafted = await run("u:x");
    expect(dash.message === DASH_MESSAGE).toBe(true);
    expect(crafted.message === FIXED_MESSAGE).toBe(true);
    expect(dash.rows.length).toBe(1);
    expect(crafted.rows.length).toBe(1);
    const [dashRow] = dash.rows;
    const [craftedRow] = crafted.rows;
    expect(dashRow).toEqual({
      eventType: "secret.use",
      secretId: "secret-1",
      principalType: "agent",
      principalId: "alice",
      sessionId: "sess-attr-1",
      detail: {
        context: "ssh",
        host: "deploy.example.com",
        port: 2222,
        user: "-l",
        error: "INVALID_SSH_CONFIG",
        interface: "rest",
      },
      success: false,
    });
    expect(Object.keys(craftedRow ?? {})).toEqual(Object.keys(dashRow ?? {}));
    expect(Object.keys(craftedRow?.detail ?? {})).toEqual(Object.keys(dashRow?.detail ?? {}));
    expect(craftedRow).toEqual({ ...dashRow, detail: { ...dashRow?.detail, user: "u:x" } });
    expect(spawnMock.mock.calls.length).toBe(0);
  });
});
