import { delimiter } from "node:path";
import { describe, expect, it } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { system32Path } from "../win32-paths.js";

// On Windows the ephemeral agent listens on a named pipe, which only the native
// Win32-OpenSSH client consumes through SSH_AUTH_SOCK; an MSYS build (the
// Git-bundled ssh a Git-Bash PATH resolves first) finds no agent and is refused
// before any spawn (D58). The git injector resolves ssh for GIT_SSH_COMMAND against
// the process PATH, so the native directory has to lead there
// (ssh-live-auth.test.ts pins the same client for the same reason).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

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
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
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

  // H1: git resolves any unambiguous prefix of a long option, so name matching
  // against the full option let `--templ=` reach --template (clone-time hook
  // execution) and `--conf=` reach --config. Verified against real git 2.51:
  // `git clone --templ=<dir>` installs hooks from <dir> and runs post-checkout.
  it.each([
    "--templ=/tmp/evil",
    "--templa=/tmp/evil",
    "--temp=/tmp/evil",
    "--conf=core.hooksPath=/tmp/evil",
    "--config-en=X=Y",
    "--upload-pa=/x",
    "--receive-pa=/y",
    "--exe=/z",
    "--separate-git-di=/tmp/evil",
    "--templ",
  ])("rejects the abbreviated form %s (git expands unambiguous prefixes)", async (arg) => {
    await expect(
      injector.executeWithSecret(gitAction({ args: [arg] }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
  });

  // Negative controls: the prefix rule must not swallow legitimate arguments
  // that merely share a leading substring with a denied option.
  it.each([
    ["--tags", "clone"],
    ["--depth=1", "clone"],
    ["--single-branch", "clone"],
    ["--set-upstream", "push"],
    ["--force", "push"],
    ["--rebase", "pull"],
    ["--exclude=x", "clone"],
  ] as const)("allows the legitimate argument %s on %s", async (arg, operation) => {
    // Passes the safety filter, so enforcement proceeds to the command allowlist
    // (deny-by-default here) rather than rejecting the argument itself.
    await expect(
      injector.executeWithSecret(
        gitAction({ operation: operation as GitAction["operation"], args: [arg] }),
        SECRET,
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
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

  it.each(["-u", "-u/tmp/evil"])("rejects the clone upload-pack shorthand %s", async (arg) => {
    await expect(
      injector.executeWithSecret(
        gitAction({ operation: "clone", args: [arg] }),
        SECRET,
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
  });

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

  // T6: the dangerous-argument matrix above only ever feeds `args`, but
  // `working_directory` reaches git's argv too — as the clone destination —
  // so without its own guard it is a second smuggling channel for exactly the
  // options that matrix rejects. Deny-by-default on the command allowlist is
  // the discriminator: rejection on the argument's *shape* happens first.
  describe("working_directory is not an argument-smuggling channel", () => {
    it.each([
      "-c",
      "--template=/tmp/evil",
      "--upload-pack=/tmp/evil",
      "--separate-git-dir=/tmp/evil",
      "--templ=/tmp/evil",
      "-",
    ])("rejects the dangerous-prefix working_directory %s", async (working_directory) => {
      const err = await injector
        .executeWithSecret(gitAction({ working_directory }), SECRET, policy(), undefined)
        .then(
          () => undefined,
          (e: unknown) => e as Error,
        );
      if (err === undefined) throw new Error("expected the call to reject");

      expect(err).toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
      expect(err.message).toContain("must not start with '-'");
    });

    it("rejects it on pull too, where it becomes the working directory", async () => {
      await expect(
        injector.executeWithSecret(
          gitAction({ operation: "pull", working_directory: "--exec=/tmp/evil" }),
          SECRET,
          policy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
    });

    it("control: an ordinary path passes the shape check and reaches the allowlist", async () => {
      await expect(
        injector.executeWithSecret(
          gitAction({ working_directory: "./checkout-dir" }),
          SECRET,
          policy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
    });
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
        allowGit({ url_allowlist: ["https://8.8.8.8/*"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_GIT_CONFIG });
  });

  it("refuses an HTTPS remote when the url_allowlist is empty (deny-by-default)", async () => {
    await expect(
      injector.executeWithSecret(
        gitAction({
          operation: "clone",
          repository: "https://8.8.8.8/repo.git",
        }),
        SECRET,
        allowGit(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
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
