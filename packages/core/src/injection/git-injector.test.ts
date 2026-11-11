import { delimiter } from "node:path";
import { describe, expect, it } from "vitest";
import type { ConnectionConfig, GitAction, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { GitInjector } from "./git-injector.js";
import { system32Path } from "../win32-paths.js";
import { expectVaultError } from "@harpoc/test-utils";

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
const SSH = resolveNativeSshClient("ssh");
// Skipped where git does not resolve; the SSH case below also needs the native ssh client.
const describeGit = describe.skipIf(GIT === null);

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
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
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

  it.each(["clone", "fetch", "ls-remote"] as const)(
    "refuses a %s of an scp-form repository whose user part holds a colon: git would contact the host before that colon, not the one the vault judges (E-20)",
    async (operation) => {
      await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({ operation, repository: "evil.invalid:x@allowed.invalid:p" }),
            SECRET,
            policy({
              command_allowlist: GIT === null ? [] : [GIT],
              host_allowlist: ["allowed.invalid"],
            }),
            undefined,
          ),
        ErrorCode.GIT_UNSUPPORTED_TRANSPORT,
      );
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
    ["--no-set-upstream", "push"],
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

  // C1 final fix X1: a relayed push cannot record an upstream in the caller's
  // tree — git writes `[branch "<b>"]` into the relay's config instead, which
  // the after-check then reports as a failed push although the remote moved.
  // The flag is refused (cluster-aware, git's abbreviations included).
  describe("X1: a push refuses -u / --set-upstream", () => {
    it.each(["-u", "--set-upstream", "--set-up", "-fu"])("refuses %s", async (arg) => {
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({
              operation: "push",
              repository: "git@github.com:org/repo.git",
              args: [arg],
              working_directory: "./wd",
            }),
            SECRET,
            policy(),
            undefined,
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toContain("disallowed git argument");
    });

    it("control: push --force-with-lease and --no-set-upstream reach the allowlist", async () => {
      await expect(
        injector.executeWithSecret(
          gitAction({
            operation: "push",
            repository: "git@github.com:org/repo.git",
            args: ["--force-with-lease", "--no-set-upstream"],
            working_directory: "./wd",
          }),
          SECRET,
          policy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
    });
  });

  // C1 final fix X3: git reads `-xyz` as -x -y -z until the first short option
  // that takes a value, so a denied letter inside a cluster is reached too.
  describe("X3: a denied short option inside a cluster is refused", () => {
    it.each([
      { operation: "clone" as const, arg: "-4u" },
      { operation: "clone" as const, arg: "-4uprog" },
      { operation: "clone" as const, arg: "-qc" },
      { operation: "clone" as const, arg: "-qcfoo=bar" },
      { operation: "pull" as const, arg: "-vc" },
      { operation: "push" as const, arg: "-qu" },
    ])("refuses $operation $arg", async ({ operation, arg }) => {
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({ operation, args: [arg], working_directory: "./wd" }),
            SECRET,
            policy(),
            undefined,
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toContain("disallowed git argument");
    });

    it.each([
      { operation: "clone" as const, arg: "-ofoo" },
      { operation: "clone" as const, arg: "-4q" },
      { operation: "clone" as const, arg: "-bcu" },
      { operation: "pull" as const, arg: "-oc" },
      { operation: "push" as const, arg: "-ou" },
    ])(
      "control: $operation $arg — the letter is the value of an earlier option — reaches the allowlist",
      async ({ operation, arg }) => {
        await expect(
          injector.executeWithSecret(
            gitAction({ operation, args: [arg], working_directory: "./wd" }),
            SECRET,
            policy(),
            undefined,
          ),
        ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
      },
    );
  });

  // C1 final fix X4a: --bundle-uri fetches an arbitrary URI the URL allowlist never saw.
  describe("X4: a clone refuses --bundle-uri", () => {
    it.each(["--bundle-uri=https://8.8.8.8/b.bundle", "--bundle-uri", "--bundle=x"])(
      "refuses %s",
      async (arg) => {
        await expectVaultError(
          () =>
            injector.executeWithSecret(
              gitAction({ args: [arg], working_directory: "./checkout-dir" }),
              SECRET,
              policy(),
              undefined,
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
      },
    );
  });

  // M6 (B9): a fetch's options reach its credential-free local step verbatim, an
  // ls-remote's its credential-bearing step; git's abbreviations measured on Git
  // for Windows 2.51 and git 2.39 (`--m` is `--multiple`, `--u` an ls-remote's
  // `--upload-pack`, `--prune` an option of its own beside `--prune-tags`).
  describe("B9: the fetch and ls-remote tables", () => {
    const run = (operation: "fetch" | "ls-remote", args: string[]) =>
      injector.executeWithSecret(
        gitAction({
          operation,
          args,
          ...(operation === "fetch" ? { working_directory: "./wd" } : {}),
        }),
        SECRET,
        policy(),
        undefined,
      );

    it.each([
      ["fetch", "-u"],
      ["fetch", "-qu"],
      ["fetch", "-vu"],
      ["fetch", "-au"],
      ["fetch", "-fu"],
      ["fetch", "-nu"],
      ["fetch", "-pu"],
      ["fetch", "-Pu"],
      ["fetch", "-ku"],
      ["fetch", "-4u"],
      ["fetch", "-6u"],
      ["fetch", "--update-head-ok"],
      ["fetch", "--update-h"],
      ["fetch", "--update-"],
      ["fetch", "-m"],
      ["fetch", "-tm"],
      ["fetch", "--multiple"],
      ["fetch", "--m"],
      ["fetch", "--all"],
      ["fetch", "--al"],
      ["fetch", "--stdin"],
      ["fetch", "--st"],
      ["fetch", "--refmap=+refs/heads/*:refs/heads/*"],
      ["fetch", "--refm=x"],
      ["fetch", "--ref"],
      ["fetch", "--set-upstream"],
      ["fetch", "--set"],
      ["fetch", "--filter=blob:none"],
      ["fetch", "--fi=blob:none"],
      ["fetch", "--upload-pack=/x"],
      ["fetch", "--upl=/x"],
      ["fetch", "--recurse-submodules"],
      ["fetch", "--recurse-submodules-default=yes"],
      ["fetch", "-c"],
      ["fetch", "--config-env=X=Y"],
      ["ls-remote", "-u"],
      ["ls-remote", "-qu"],
      ["ls-remote", "-tu"],
      ["ls-remote", "-bu"],
      ["ls-remote", "-hu"],
      ["ls-remote", "--upload-pack=/x"],
      ["ls-remote", "--u=/x"],
      ["ls-remote", "--exec=/x"],
      ["ls-remote", "--exe=/x"],
      ["ls-remote", "--ex"],
      ["ls-remote", "-c"],
      ["ls-remote", "--conf=k=v"],
      ["ls-remote", "--recurse-submodules"],
    ] as const)("%s refuses %s", async (operation, arg) => {
      const err = await expectVaultError(() => run(operation, [arg]), ErrorCode.INVALID_GIT_CONFIG);
      expect(err.message).toBe(`disallowed git argument: ${arg}`);
    });

    it("fetch refuses -o -u: a separated value is judged as a token of its own, so a dash-led one that spells a denied option is refused (F1-R1)", async () => {
      const err = await expectVaultError(
        () => run("fetch", ["-o", "-u"]),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe("disallowed git argument: -u");
    });

    it.each([
      ["fetch", "--update-shallow"],
      ["fetch", "--unshallow"],
      ["fetch", "--prune"],
      ["fetch", "-p"],
      ["fetch", "--prune-tags"],
      ["fetch", "-P"],
      ["fetch", "--tags"],
      ["fetch", "-t"],
      ["fetch", "-n"],
      ["fetch", "--no-tags"],
      ["fetch", "--force"],
      ["fetch", "-f"],
      ["fetch", "--append"],
      ["fetch", "--atomic"],
      ["fetch", "--dry-run"],
      ["fetch", "--depth=1"],
      ["fetch", "--deepen=2"],
      ["fetch", "--shallow-since=2026-01-01"],
      ["fetch", "--refetch"],
      ["fetch", "--server-option=x"],
      ["fetch", "-ou"],
      ["fetch", "-ju"],
      ["fetch", "--jobs=2"],
      ["fetch", "--no-recurse-submodules"],
      ["fetch", "--no-write-fetch-head"],
      ["fetch", "--porcelain"],
      ["fetch", "--prefetch"],
      ["fetch", "--negotiation-tip=refs/heads/main"],
      ["fetch", "--auto-maintenance"],
      ["fetch", "--write-commit-graph"],
      ["fetch", "--show-forced-updates"],
      ["fetch", "-k"],
      ["fetch", "-4"],
      ["fetch", "-qv"],
      ["ls-remote", "--symref"],
      ["ls-remote", "--heads"],
      ["ls-remote", "--branches"],
      ["ls-remote", "-b"],
      ["ls-remote", "--tags"],
      ["ls-remote", "-t"],
      ["ls-remote", "--refs"],
      ["ls-remote", "-q"],
      ["ls-remote", "--exit-code"],
      ["ls-remote", "--exi"],
      ["ls-remote", "--get-url"],
      ["ls-remote", "--sort=-version:refname"],
      ["ls-remote", "--server-option=x"],
      ["ls-remote", "-ou"],
    ] as const)("control: %s admits %s (it reaches the allowlist)", async (operation, arg) => {
      await expect(run(operation, [arg])).rejects.toMatchObject({
        code: ErrorCode.COMMAND_NOT_ALLOWED,
      });
    });

    it.each(["origin", "main", "refs/heads/x", "-", "--", "--end-of-options"])(
      "a fetch takes no positional argument: %s",
      async (arg) => {
        const err = await expectVaultError(() => run("fetch", [arg]), ErrorCode.INVALID_GIT_CONFIG);
        expect(err.message).toBe(`a fetch takes no positional argument: ${arg}`);
      },
    );

    it.each(["origin", "https://8.8.4.4/other.git", "refs/heads/*", "--"])(
      "an ls-remote takes no positional argument: %s",
      async (arg) => {
        const err = await expectVaultError(
          () => run("ls-remote", [arg]),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe(`an ls-remote takes no positional argument: ${arg}`);
      },
    );

    it.each(["clone", "pull", "push", "ls-remote"] as const)(
      "refspecs on a %s is refused",
      async (operation) => {
        const err = await expectVaultError(
          () =>
            injector.executeWithSecret(
              gitAction({ operation, refspecs: ["refs/heads/main"], working_directory: "./wd" }),
              SECRET,
              policy(),
              undefined,
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toBe("refspecs is only accepted by a fetch");
      },
    );

    it("an empty refspecs list on a fetch is refused", async () => {
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({ operation: "fetch", refspecs: [], working_directory: "./wd" }),
            SECRET,
            policy(),
            undefined,
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe("refspecs must not be empty");
    });

    it("a fetch refspec outside the grammar is refused before the allowlist, naming it", async () => {
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({
              operation: "fetch",
              refspecs: ["refs/heads/a:refs/heads/b"],
              working_directory: "./wd",
            }),
            SECRET,
            policy(),
            undefined,
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe("unsupported fetch refspec: refs/heads/a:refs/heads/b");
    });

    it("negative refspecs alone are refused", async () => {
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({
              operation: "fetch",
              refspecs: ["^refs/heads/wip"],
              working_directory: "./wd",
            }),
            SECRET,
            policy(),
            undefined,
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toBe("a fetch needs a refspec that is not negative: ^refs/heads/wip");
    });

    it("control: admitted refspecs reach the allowlist", async () => {
      await expect(
        injector.executeWithSecret(
          gitAction({
            operation: "fetch",
            refspecs: ["+refs/heads/*", "^refs/heads/wip/*", "refs/tags/v*"],
            working_directory: "./wd",
          }),
          SECRET,
          policy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
    });
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
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(gitAction({ working_directory }), SECRET, policy(), undefined),
        ErrorCode.INVALID_GIT_CONFIG,
      );
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

  // S5 (code review 2026-10-15): without working_directory git reads a second
  // positional as the destination, so `clone <arg> -- <repository>` clones
  // `<arg>` — a host the allowlist never saw — into a directory named after
  // the validated URL. The refusal comes before the command allowlist.
  describe("S5: a clone without working_directory takes no positional argument", () => {
    it.each([
      "https://8.8.8.8/org/other.git",
      "/tmp/local-repo",
      "1",
      "-",
      "--",
      "--end-of-options",
    ])("refuses %s", async (arg) => {
      const err = await expectVaultError(
        () => injector.executeWithSecret(gitAction({ args: [arg] }), SECRET, policy(), undefined),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toContain("takes no positional argument");
    });

    it("control: --option=value without working_directory, and a separate value with it, reach the allowlist", async () => {
      for (const action of [
        gitAction({ args: ["--depth=1", "-bmain"] }),
        gitAction({ args: ["--depth", "1"], working_directory: "./checkout-dir" }),
      ]) {
        await expect(
          injector.executeWithSecret(action, SECRET, policy(), undefined),
        ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
      }
    });
  });

  // S1 (fix round 1, F-1): a clone's transfer runs into the vault's relay in
  // full and the caller's clone is made from it, so a partial-clone filter
  // would leave a promisor origin whose lazy fetches run without the
  // credential. A clone refuses the filter family before any spawn.
  describe("S1: a clone takes no partial-clone filter", () => {
    it.each([
      "--filter=blob:none",
      "--filter",
      "--filt=tree:0",
      "--also-filter-submodules",
      "--also-filter",
    ])("refuses %s", async (arg) => {
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({ args: [arg], working_directory: "./checkout-dir" }),
            SECRET,
            policy(),
            undefined,
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toContain("disallowed git argument");
    });

    it("control: the negations, and --filter on a pull, reach the allowlist", async () => {
      for (const action of [
        gitAction({ args: ["--no-filter", "--no-also-filter-submodules"] }),
        gitAction({ operation: "pull", args: ["--filter=blob:none"], working_directory: "./wd" }),
      ]) {
        await expect(
          injector.executeWithSecret(action, SECRET, policy(), undefined),
        ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
      }
    });
  });

  // C1 final fix X2: a pull's positional would be git's repository for the
  // credential-free local pull, with the vault's `-- <repository>` demoted to a
  // refspec — an scp-form URL is a valid refspec, so the local pull connects to
  // the positional's host. A pull takes option-shaped arguments only.
  describe("X2: a pull takes no positional argument", () => {
    it.each(["git@evil.example:x/y.git", "origin", "main", "-", "--", "--end-of-options"])(
      "refuses %s",
      async (arg) => {
        const err = await expectVaultError(
          () =>
            injector.executeWithSecret(
              gitAction({ operation: "pull", args: [arg], working_directory: "./wd" }),
              SECRET,
              policy(),
              undefined,
            ),
          ErrorCode.INVALID_GIT_CONFIG,
        );
        expect(err.message).toContain("a pull takes no positional argument");
      },
    );

    it("control: option-shaped pull arguments reach the allowlist", async () => {
      await expect(
        injector.executeWithSecret(
          gitAction({
            operation: "pull",
            args: ["--ff-only", "--depth=1", "-Xours", "--rebase=false"],
            working_directory: "./wd",
          }),
          SECRET,
          policy(),
          undefined,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
    });
  });

  // S5 (fix round 1, F-2): a positional in a push's args would be git's
  // repository and the vault's trailing `-- <repository>` a refspec. git aborts
  // on that refspec before connecting today, but only by accident, so the push
  // takes option-shaped arguments only, as a clone without working_directory does.
  describe("S5: a push takes no positional argument", () => {
    it.each([
      "https://8.8.8.8/org/other.git",
      "main",
      "HEAD:refs/heads/other",
      "-",
      "--",
      "--end-of-options",
    ])("refuses %s", async (arg) => {
      const err = await expectVaultError(
        () =>
          injector.executeWithSecret(
            gitAction({ operation: "push", args: [arg], working_directory: "./wd" }),
            SECRET,
            policy(),
            undefined,
          ),
        ErrorCode.INVALID_GIT_CONFIG,
      );
      expect(err.message).toContain("a push takes no positional argument");
    });

    it("control: option-shaped push arguments reach the allowlist", async () => {
      await expect(
        injector.executeWithSecret(
          gitAction({
            operation: "push",
            args: ["--force-with-lease", "--push-option=ci.skip", "-otrace"],
            working_directory: "./wd",
          }),
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

  it.each([
    ["git@github.com:org/repo.git", "github.com"],
    ["user.name@host.example:path", "host.example"],
  ])("still reads %s as SSH and judges the host %s (E-20 controls)", async (repository, host) => {
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          gitAction({ repository }),
          SECRET,
          allowGit({ host_allowlist: ["allowed.invalid"] }),
          undefined,
        ),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    expect(err.message).toBe(`Host not in secret allowlist: ${host}`);
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

  it("refuses an SSH remote when the host_allowlist is empty (deny-by-default)", async () => {
    const config: ConnectionConfig = {
      ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABOGUS"] },
    };
    await expect(
      injector.executeWithSecret(
        gitAction({ operation: "clone", repository: "git@github.com:org/repo.git" }),
        SECRET,
        allowGit(),
        config,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
  });

  it.skipIf(SSH === null)(
    "accepts an allowlisted SSH remote config shape (reaches agent start)",
    async () => {
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
    },
  );
});
