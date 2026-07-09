import { describe, expect, it } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";

const GIT = resolveExecutable("git", controlledPathDirs());
const describeGit = GIT ? describe : describe.skip;

const SECRET = new Uint8Array(Buffer.from("ghp_testtoken"));

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

function gitAction(overrides: Partial<GitAction> = {}): GitAction {
  return {
    type: "git",
    operation: "clone",
    repository: "https://github.com/user/repo.git",
    ...overrides,
  };
}

describe("GitInjector enforcement (no git binary required)", () => {
  const injector = new GitInjector(null);

  it.each(["ext::sh -c whoami", "file:///etc/passwd", "git+ssh://x/y"])(
    "rejects forbidden transport %s",
    async (repository) => {
      await expect(
        injector.executeWithSecret(gitAction({ repository }), SECRET, policy(), undefined),
      ).rejects.toMatchObject({ code: ErrorCode.GIT_UNSUPPORTED_TRANSPORT });
    },
  );

  it.each([
    "-c",
    "--config",
    "--upload-pack=/x",
    "--receive-pack=/y",
    "--exec=/z",
    "--template=/tmp/evil",
    "--separate-git-dir=/tmp/evil",
  ])("rejects dangerous git argument %s", async (arg) => {
    await expect(
      injector.executeWithSecret(gitAction({ args: [arg] }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
  });

  it("rejects --template in its space-separated form (value arg alone is inert)", async () => {
    await expect(
      injector.executeWithSecret(
        gitAction({ args: ["--template", "/tmp/evil"] }),
        SECRET,
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
  });

  it.each(["-u", "-u/tmp/evil"])(
    "rejects the clone upload-pack shorthand %s",
    async (arg) => {
      await expect(
        injector.executeWithSecret(
          gitAction({ operation: "clone", args: [arg] }),
          SECRET,
          policy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
    },
  );

  it("allows push -u (--set-upstream) — the shorthand is clone-only dangerous", async () => {
    // -u is benign for push; args pass the safety filter and enforcement proceeds
    // past it to the command allowlist (deny-by-default here), not INVALID_GIT_CONFIG.
    await expect(
      injector.executeWithSecret(
        gitAction({
          operation: "push",
          repository: "git@github.com:org/repo.git",
          args: ["-u", "origin", "main"],
        }),
        SECRET,
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });

  it("denies git by default when no command allowlist is set", async () => {
    await expect(
      injector.executeWithSecret(gitAction(), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
  });
});

describeGit("GitInjector target enforcement (git resolvable)", () => {
  const injector = new GitInjector(null);
  const allowGit = (overrides: Partial<InjectionPolicy> = {}) =>
    policy({ command_allowlist: [GIT as string], ...overrides });

  it("rejects a plaintext http remote (HTTPS required)", async () => {
    await expect(
      injector.executeWithSecret(
        gitAction({ repository: "http://8.8.8.8/repo.git" }),
        SECRET,
        allowGit(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.URL_HTTPS_REQUIRED });
  });

  it("rejects an HTTPS remote outside the URL allowlist", async () => {
    await expect(
      injector.executeWithSecret(
        gitAction({ repository: "https://8.8.8.8/evil.git" }),
        SECRET,
        allowGit({ url_allowlist: ["https://github.com/*"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
  });

  it("rejects an SSH remote host outside the host allowlist", async () => {
    await expect(
      injector.executeWithSecret(
        gitAction({ operation: "push", repository: "git@evil.example.com:org/repo.git" }),
        SECRET,
        allowGit({ host_allowlist: ["github.com"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
  });

  it("requires pinned host keys for an allowlisted SSH remote", async () => {
    await expect(
      injector.executeWithSecret(
        gitAction({ operation: "push", repository: "git@github.com:org/repo.git" }),
        SECRET,
        allowGit({ host_allowlist: ["github.com"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_NOT_CONFIGURED });
  });

  it("requires working_directory for pull/push", async () => {
    await expect(
      injector.executeWithSecret(
        gitAction({ operation: "pull", repository: "https://8.8.8.8/repo.git" }),
        SECRET,
        allowGit(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
  });

  it("accepts an allowlisted SSH remote config shape (reaches agent start)", async () => {
    // github.com allowlisted + a (bogus) pinned key: the injector proceeds past
    // target validation. We only assert it does NOT reject on policy grounds.
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABOGUS"] },
    };
    const badKey = new Uint8Array(Buffer.from("not-a-valid-key"));
    await expect(
      injector.executeWithSecret(
        gitAction({ operation: "clone", repository: "git@github.com:org/repo.git" }),
        badKey,
        allowGit({ host_allowlist: ["github.com"] }),
        config,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_AGENT_FAILED });
  });
});
