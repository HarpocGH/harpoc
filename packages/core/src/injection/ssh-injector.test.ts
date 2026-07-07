import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SshAction } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { SshInjector } from "./ssh-injector.js";

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
      injector.executeWithSecret(ACTION, SECRET, policy({ host_allowlist: ["other.example.com"] }), SSH_CONFIG),
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
});
