import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { GitAction, GitOperation } from "@harpoc/shared";
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
 *
 * RX-B9-12 (B9): every refusal the git injector throws before the spawn writes
 * one failed `secret.use` row naming the context, the operation and the code —
 * never the refused argument, refspec or path.
 */

const PASSWORD = "integration-test-pw";
const GIT_SECRET = "x-access-token:ghp_git-secret-abcd";
const TOKEN_FRAGMENT = "ghp_git-secret";
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

  /** The refusal's code, and its one failed row carrying none of `refused` nor the token. */
  async function expectAuditedRefusal(
    action: GitAction,
    refused: string[],
    code: ErrorCode = ErrorCode.INVALID_GIT_CONFIG,
  ): Promise<void> {
    await expectVaultError(() => client.useSecret(handle, action), code);
    const rows = vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: false,
      detail: { context: "git", operation: action.operation, error: code },
    });
    const keys = Object.keys(rows[0]?.detail ?? {});
    expect(keys.sort()).toEqual(["context", "error", "operation"]);
    const text = JSON.stringify(rows);
    for (const needle of refused) {
      expect(text.includes(JSON.stringify(needle).slice(1, -1)), needle).toBe(false);
    }
    expect(text.includes(TOKEN_FRAGMENT)).toBe(false);
  }

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
    await expectAuditedRefusal(
      {
        type: "git",
        operation: "clone",
        repository: "https://8.8.8.8/org/repo.git",
        args: ["--config", "core.fsmonitor=/tmp/evil"],
      },
      ["--config", "core.fsmonitor", "/tmp/evil"],
    );
  });

  // M6 (B9): `-u` is `--update-head-ok` on fetch and no option of ls-remote,
  // refused on both, as `--upload-pack` is on every operation. Each value is
  // attached, so no positional stands in for the refusal; the repository is a
  // literal IP outside the allowlist, so a refusal that went missing surfaces
  // as URL_NOT_ALLOWED, never as a lookup or a connection.
  const M6_REFUSED: ReadonlyArray<readonly [GitOperation, string[]]> = [
    ["fetch", ["-u"]],
    ["fetch", ["--upload-pack=/tmp/evil"]],
    ["ls-remote", ["-u/tmp/evil"]],
    ["ls-remote", ["--upload-pack=/tmp/evil"]],
  ];

  it.each(M6_REFUSED)("M6: %s refuses %j", async (operation, args) => {
    await expectAuditedRefusal(
      {
        type: "git",
        operation,
        repository: "https://8.8.8.8/org/repo.git",
        args,
        ...(operation === "fetch" ? { working_directory: vault.tmpDir } : {}),
      },
      ["/tmp/evil", "--upload-pack"],
    );
  });

  // M6 (B9): the engine path parses no schema (DirectClient hands the action to
  // VaultEngine.useSecret as it is), so the injector itself refuses refspecs on
  // an operation other than fetch, a working tree on ls-remote and an
  // operation that is not one of the five (RX-B9-13: before B9 the engine ran
  // a pull for it).
  it("M6: a pull carrying refspecs is refused", async () => {
    await expectAuditedRefusal(
      {
        type: "git",
        operation: "pull",
        repository: "https://8.8.8.8/org/repo.git",
        working_directory: vault.tmpDir,
        refspecs: ["refs/heads/release-candidate"],
      },
      ["refs/heads/release-candidate", vault.tmpDir],
    );
  });

  // The working-tree check sits behind the URL checks, so the repository is
  // allowlisted on loopback: a refusal that went missing meets a closed port.
  it("M6: ls-remote with a working_directory is refused", async () => {
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: ["http://127.0.0.1:9/*"],
      command_allowlist: [GIT as string],
      env_allowlist: [],
      host_allowlist: [],
    });
    await expectAuditedRefusal(
      {
        type: "git",
        operation: "ls-remote",
        repository: "http://127.0.0.1:9/repo.git",
        working_directory: vault.tmpDir,
      },
      [vault.tmpDir],
    );
  });

  it("M6: an operation that is not one of the five is refused", async () => {
    await expectAuditedRefusal(
      {
        type: "git",
        operation: "bogus",
        repository: "https://8.8.8.8/org/repo.git",
        working_directory: vault.tmpDir,
      } as unknown as GitAction,
      [vault.tmpDir],
    );
  });

  // E-19 (B9): a repository that begins with `-` would be read as an option —
  // with a value-taking `-o` in args, git takes `--` as that value and runs the
  // scp-shaped `--upload-pack=x@<host>:p` as an upload-pack program. Refused in
  // the pre-flight before any git process; with the check missing, the host
  // (allowlisted here) meets the absent known-host pin, SSH_NOT_CONFIGURED,
  // still before any spawn.
  const DASH_LED: ReadonlyArray<readonly [GitOperation, boolean]> = [
    ["push", true],
    ["fetch", true],
    ["ls-remote", false],
  ];

  it.each(DASH_LED)(
    "E-19: %s refuses a repository that begins with '-'",
    async (operation, tree) => {
      await expectAuditedRefusal(
        {
          type: "git",
          operation,
          repository: "--upload-pack=x@github.com:p",
          args: ["-o"],
          ...(tree ? { working_directory: vault.tmpDir } : {}),
        },
        ["--upload-pack", "x@github.com"],
      );
    },
  );

  // E-20 (B9): the scp form's user part admits no colon, so
  // `evil.invalid:x@github.com:p` is no SSH repository — the vault would judge
  // `github.com` while git hands ssh `evil.invalid`. Refused as an unsupported
  // transport before any git process; with only `detectTransport`'s pattern
  // widened back, `parseSshHost` finds no host (INVALID_GIT_CONFIG), and with
  // `parseSshHost` widened as well, the allowlisted host meets the absent
  // known-host pin, either way still before any spawn.
  const COLON_USER: ReadonlyArray<readonly [GitOperation, boolean]> = [
    ["pull", true],
    ["ls-remote", false],
  ];

  it.each(COLON_USER)(
    "E-20: %s refuses an scp-form repository whose user part holds a colon",
    async (operation, tree) => {
      await expectAuditedRefusal(
        {
          type: "git",
          operation,
          repository: "evil.invalid:x@github.com:p",
          ...(tree ? { working_directory: vault.tmpDir } : {}),
        },
        ["evil.invalid"],
        ErrorCode.GIT_UNSUPPORTED_TRANSPORT,
      );
    },
  );

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
    expect(err.message.includes(TOKEN_FRAGMENT)).toBe(false);
    expect(String(err.stack).includes(TOKEN_FRAGMENT)).toBe(false);
    expect(JSON.stringify(err).includes(TOKEN_FRAGMENT)).toBe(false);
  });
});
