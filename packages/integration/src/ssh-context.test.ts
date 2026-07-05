import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

/**
 * SSH context (thesis §4.5.7, §6.2 host-redirection). Deterministic enforcement:
 * a redirect to an unlisted host is rejected before authentication; pinned host
 * keys are mandatory (no TOFU); the ssh binary must be command-allowlisted. The
 * key is served through the ephemeral in-process agent and never touches disk.
 * Live connections are out of scope for CI; these are Tier-1 enforcement tests.
 */

const PASSWORD = "integration-test-pw";

function makeKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
}

function sshAction(host: string) {
  return { type: "ssh" as const, host, user: "deploy", command: "whoami" };
}

describe("SSH context (process-mediated, §4.5.7)", () => {
  let vault: TestVault;
  let handle: string;
  let client: DirectClient;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "ssh-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(makeKeyPem(), "utf8")),
    });
    handle = created.handle;
    client = new DirectClient(vault.engine);
  });

  afterEach(async () => {
    await destroyTestVault(vault);
  });

  it("denies by default when no host allowlist is set (fail-safe)", async () => {
    await expect(client.useSecret(handle, sshAction("deploy.example.com"))).rejects.toMatchObject({
      code: ErrorCode.HOST_NOT_ALLOWED,
    });
  });

  it("blocks a redirect to an unlisted host", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: ["ssh"],
      env_allowlist: [],
      host_allowlist: ["deploy.example.com"],
    });
    await vault.engine.setConnectionConfig(handle, {
      ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAA"] },
    });
    await expect(client.useSecret(handle, sshAction("attacker.example.com"))).rejects.toMatchObject({
      code: ErrorCode.HOST_NOT_ALLOWED,
    });
  });

  it("requires pinned host keys (no trust-on-first-use)", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: ["ssh"],
      env_allowlist: [],
      host_allowlist: ["deploy.example.com"],
    });
    await expect(client.useSecret(handle, sshAction("deploy.example.com"))).rejects.toMatchObject({
      code: ErrorCode.SSH_NOT_CONFIGURED,
    });
  });

  it("requires the ssh binary to be command-allowlisted", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["deploy.example.com"],
    });
    await vault.engine.setConnectionConfig(handle, {
      ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAA"] },
    });
    await expect(client.useSecret(handle, sshAction("deploy.example.com"))).rejects.toMatchObject({
      code: ErrorCode.COMMAND_NOT_ALLOWED,
    });
  });

  it("I1: the private key never appears in a rejection", async () => {
    try {
      await client.useSecret(handle, sshAction("deploy.example.com"));
      expect.fail("should throw");
    } catch (e) {
      expect(JSON.stringify(e)).not.toContain("PRIVATE KEY");
    }
  });
});
