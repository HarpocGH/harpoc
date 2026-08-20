import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SftpAction } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { buildSftpAuditDetails, executeSftpAction } from "./sftp-injector.js";

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

describe("buildSftpAuditDetails", () => {
  it("names host, operation and remote/local paths from the action (design §7.2)", () => {
    expect(
      buildSftpAuditDetails({
        type: "sftp",
        host: "deploy.example.com",
        user: "deploy",
        operation: "upload",
        remote_path: "/srv/report.pdf",
        local_path: "/tmp/report.pdf",
      }),
    ).toEqual({
      host: "deploy.example.com",
      operation: "upload",
      remote_path: "/srv/report.pdf",
      local_path: "/tmp/report.pdf",
    });
  });

  it("reports local_path as null for a list operation", () => {
    expect(buildSftpAuditDetails(ACTION)).toEqual({
      host: "deploy.example.com",
      operation: "list",
      remote_path: "/srv/reports",
      local_path: null,
    });
  });
});
