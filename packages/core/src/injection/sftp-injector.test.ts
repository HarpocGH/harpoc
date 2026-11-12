import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SftpAction } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { buildSftpAuditDetails, executeSftpAction } from "./sftp-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
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

const ACTION: SftpAction = {
  type: "sftp",
  host: "deploy.example.com",
  user: "deploy",
  operation: "list",
  remote_path: "/srv/reports",
};

const SFTP_CONFIG: ConnectionConfig = {
  ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};

describe("executeSftpAction enforcement", () => {
  it("denies by default when the host allowlist is empty (fail-safe)", async () => {
    await expect(executeSftpAction(ACTION, SECRET, policy(), SFTP_CONFIG)).rejects.toMatchObject({
      code: ErrorCode.HOST_NOT_ALLOWED,
    });
  });

  it("denies a host outside the allowlist", async () => {
    await expect(
      executeSftpAction(
        ACTION,
        SECRET,
        policy({ host_allowlist: ["other.example.com"] }),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
  });

  it("requires pinned host keys (no TOFU)", async () => {
    await expect(
      executeSftpAction(
        ACTION,
        SECRET,
        policy({ host_allowlist: ["deploy.example.com"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_NOT_CONFIGURED });
  });

  it("requires the sftp binary to be command-allowlisted (fail-safe deny)", async () => {
    await expect(
      executeSftpAction(
        ACTION,
        SECRET,
        policy({ host_allowlist: ["deploy.example.com"] }),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });

  it("refuses a host starting with '-' before any other work (argv option smuggling)", async () => {
    await expect(
      executeSftpAction(
        { ...ACTION, host: "-oProxyCommand.evil" },
        SECRET,
        policy({ host_allowlist: ["-oProxyCommand.evil"] }),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_SSH_CONFIG });
  });

  it("refuses a user starting with '-'", async () => {
    await expect(
      executeSftpAction(
        { ...ACTION, user: "-l" },
        SECRET,
        policy({ host_allowlist: ["deploy.example.com"] }),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_SSH_CONFIG });
  });
});

const FIXED_MESSAGE = "host and user must be names of letters, digits, '.', '_' and '-'";
const DASH_MESSAGE = "host and user must not start with '-'";

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
  ["a : that ends sftp's host part", "evil.example:sub"],
  ["an sftp:// URI", "sftp://x@evil.example:2222/"],
  ["an @ and brackets", "u@[evil.example]"],
];

describe("a host or user outside the schema's charset is refused before the allowlist", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  async function expectRefused(
    action: SftpAction,
    allowed: string,
    refused: string,
  ): Promise<void> {
    const err = await expectVaultError(
      () => executeSftpAction(action, SECRET, policy({ host_allowlist: [allowed] }), SFTP_CONFIG),
      ErrorCode.INVALID_SSH_CONFIG,
    );
    expect(err.message.includes(refused)).toBe(false);
    expect(err.message === FIXED_MESSAGE).toBe(true);
    expect(spawnMock.mock.calls.length).toBe(0);
  }

  it.each(NOT_A_NAME_HOSTS)(
    "a host with %s, admitted by the allowlist: INVALID_SSH_CONFIG, nothing spawned",
    (_label, host) => expectRefused({ ...ACTION, host }, host, host),
  );

  it.each(NOT_A_NAME_USERS)("a user with %s: INVALID_SSH_CONFIG, nothing spawned", (_label, user) =>
    expectRefused({ ...ACTION, user }, ACTION.host, user),
  );

  it("a host outside the charset that the allowlist does not admit: INVALID_SSH_CONFIG, not HOST_NOT_ALLOWED", () =>
    expectRefused({ ...ACTION, host: "ok.example:2222" }, ACTION.host, "ok.example:2222"));

  it("a dash-led user still meets the leading-dash refusal first, its message unchanged", async () => {
    const err = await expectVaultError(
      () =>
        executeSftpAction(
          { ...ACTION, user: "-l" },
          SECRET,
          policy({ host_allowlist: [ACTION.host] }),
          SFTP_CONFIG,
        ),
      ErrorCode.INVALID_SSH_CONFIG,
    );
    expect(err.message === DASH_MESSAGE).toBe(true);
    expect(spawnMock.mock.calls.length).toBe(0);
  });
});

const NON_STRINGS: ReadonlyArray<readonly [string, unknown]> = [
  ["a number", 5],
  ["undefined", undefined],
  ["null", null],
  ["an array", ["-x"]],
  ["an object", {}],
];

const NON_STRING_FIELDS = (["host", "user"] as const).flatMap((field) =>
  NON_STRINGS.map(([label, value]) => [field, label, value] as const),
);

describe("a non-string host or user of an unparsed caller is refused with the charset refusal", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it.each(NON_STRING_FIELDS)(
    "a %s that is %s: INVALID_SSH_CONFIG with the charset message, a row projection without the field, nothing spawned",
    async (field, _label, value) => {
      const action = { ...ACTION, [field]: value } as unknown as SftpAction;
      const err = await expectVaultError(
        () =>
          executeSftpAction(action, SECRET, policy({ host_allowlist: [ACTION.host] }), SFTP_CONFIG),
        ErrorCode.INVALID_SSH_CONFIG,
      );
      expect(err.message === FIXED_MESSAGE).toBe(true);
      const kept = field === "host" ? {} : { host: ACTION.host };
      expect(buildSftpAuditDetails(action, policy())).toStrictEqual({
        ...kept,
        operation: "list",
        port: null,
        remote_path: "/srv/reports",
        local_path: null,
        network_isolation: false,
        fs_isolation: false,
      });
      expect(spawnMock.mock.calls.length).toBe(0);
    },
  );
});

const PATH_DASH_MESSAGE = "sftp path must not start with '-' (would be parsed as an sftp option)";
const LOCAL_PATH_REQUIRED = "local_path is required for upload";

const NON_STRING_LOCAL_PATHS: ReadonlyArray<readonly [string, unknown, string]> = [
  ["a number", 5, PATH_DASH_MESSAGE],
  ["undefined", undefined, LOCAL_PATH_REQUIRED],
  ["null", null, LOCAL_PATH_REQUIRED],
  ["an array", ["-x"], PATH_DASH_MESSAGE],
  ["an object", {}, PATH_DASH_MESSAGE],
];

describe("a non-string remote_path or local_path of an unparsed caller is refused like a malformed path", () => {
  const spawnMock = vi.mocked(spawnCaptured);
  let binDir: string;
  let sftpPath: string;
  let savedPath: string | undefined;

  beforeEach(() => {
    spawnMock.mockReset();
    binDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-sftp-bin-")));
    sftpPath = join(binDir, process.platform === "win32" ? "sftp.exe" : "sftp");
    writeFileSync(sftpPath, "", { mode: 0o755 });
    savedPath = process.env.PATH;
    process.env.PATH = binDir + delimiter + (savedPath ?? "");
  });

  afterEach(() => {
    if (savedPath === undefined) delete process.env.PATH;
    else process.env.PATH = savedPath;
    rmSync(binDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  function allowed(): InjectionPolicy {
    return policy({ host_allowlist: [ACTION.host], command_allowlist: [sftpPath] });
  }

  it.each(NON_STRINGS)(
    "a remote_path that is %s: INVALID_INPUT with the leading-dash path message, a row projection without remote_path, nothing spawned",
    async (_label, value) => {
      const action = { ...ACTION, remote_path: value } as unknown as SftpAction;
      const err = await expectVaultError(
        () => executeSftpAction(action, SECRET, allowed(), SFTP_CONFIG),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message === PATH_DASH_MESSAGE).toBe(true);
      expect(buildSftpAuditDetails(action, policy())).toStrictEqual({
        host: ACTION.host,
        operation: "list",
        port: null,
        local_path: null,
        network_isolation: false,
        fs_isolation: false,
      });
      expect(spawnMock.mock.calls.length).toBe(0);
    },
  );

  it.each(NON_STRING_LOCAL_PATHS)(
    "an upload's local_path that is %s: INVALID_INPUT with the message the malformed path meets today, local_path null in the row projection, nothing spawned",
    async (_label, value, message) => {
      const action = {
        ...ACTION,
        operation: "upload",
        remote_path: "/srv/report.pdf",
        local_path: value,
      } as unknown as SftpAction;
      const err = await expectVaultError(
        () => executeSftpAction(action, SECRET, allowed(), SFTP_CONFIG),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message === message).toBe(true);
      expect(buildSftpAuditDetails(action, policy())).toStrictEqual({
        host: ACTION.host,
        operation: "upload",
        port: null,
        remote_path: "/srv/report.pdf",
        local_path: null,
        network_isolation: false,
        fs_isolation: false,
      });
      expect(spawnMock.mock.calls.length).toBe(0);
    },
  );
});

describe("buildSftpAuditDetails", () => {
  it("names host, operation and remote/local paths from the action (design §7.2)", () => {
    expect(
      buildSftpAuditDetails(
        {
          type: "sftp",
          host: "deploy.example.com",
          user: "deploy",
          operation: "upload",
          remote_path: "/srv/report.pdf",
          local_path: "/tmp/report.pdf",
        },
        policy(),
      ),
    ).toEqual({
      host: "deploy.example.com",
      operation: "upload",
      port: null,
      remote_path: "/srv/report.pdf",
      local_path: "/tmp/report.pdf",
      network_isolation: false,
      fs_isolation: false,
    });
  });

  it("reports local_path as null for a list operation", () => {
    expect(buildSftpAuditDetails(ACTION, policy())).toEqual({
      host: "deploy.example.com",
      operation: "list",
      port: null,
      remote_path: "/srv/reports",
      local_path: null,
      network_isolation: false,
      fs_isolation: false,
    });
  });

  it("carries a non-22 port and reports null when the action names none", () => {
    expect(buildSftpAuditDetails({ ...ACTION, port: 2222 }, policy()).port).toBe(2222);
    expect(buildSftpAuditDetails(ACTION, policy()).port).toBeNull();
  });

  it("carries the policy's isolation flags on every row — the posture the other spawned contexts record (2026-10-14)", () => {
    expect(
      buildSftpAuditDetails(ACTION, policy({ network_isolation: true, fs_isolation: true })),
    ).toMatchObject({ network_isolation: true, fs_isolation: true });
  });
});
