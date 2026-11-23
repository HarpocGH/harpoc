import { describe, expect, it } from "vitest";
import {
  HOOK_EVENTS_AT_V2_56_1,
  LOCAL_STEP_VARIABLES,
  localEnvironment,
  localStepWords,
  REPOSITORY_VARIABLES,
} from "./__fixtures__/git-local-steps.js";
import {
  GIT_HOOK_EVENTS,
  judgeOwnConfig,
  localStepConfig,
  OWN_CONFIG_PATTERN,
  ownConfigListingArgs,
  removeRepositoryVariables,
  writeLocalStepVariables,
} from "./git-injector-local-steps.js";

const PATTERN =
  "^(hook\\..*\\.command|filter\\..*\\.(smudge|clean|process)|merge\\..*\\.driver|url\\..*\\.(insteadof|pushinsteadof)|remote\\..*|remotes\\..*|extensions\\.partialclone|fetch\\.bundleuri|http\\.(.*\\.)?proactiveauth|core\\.(alternaterefscommand|sshcommand|gitproxy|askpass|editor|attributesfile)|sequence\\.editor|gc\\.recentobjectshook|gpg\\.program|gpg\\..*\\.(program|defaultkeycommand)|protocol\\..*\\.allow)$";

const ADDRESS = "https://8.8.8.8/org/repo.git";
const MEASURED_ADDRESS = "https://git.example.invalid/remote.git";

const NO_HIT = { hookCommand: false, remoteGroup: false, programOrRewrite: false };
const HOOK = { hookCommand: true, remoteGroup: false, programOrRewrite: false };
const PROGRAM = { hookCommand: false, remoteGroup: false, programOrRewrite: true };
const GROUP = { hookCommand: false, remoteGroup: true, programOrRewrite: false };

const LISTED_NAMES: ReadonlyArray<readonly [string, typeof HOOK]> = [
  ["hook.r2b.command", HOOK],
  ["filter.f.smudge", PROGRAM],
  ["filter.f.clean", PROGRAM],
  ["filter.f.process", PROGRAM],
  ["filter.Dotted.Name.With.CAPS.smudge", PROGRAM],
  ["merge.m.driver", PROGRAM],
  ["url./srv/elsewhere.insteadof", PROGRAM],
  ["url./srv/elsewhere.pushinsteadof", PROGRAM],
  [`remote.${MEASURED_ADDRESS}.url`, PROGRAM],
  [`remote.${MEASURED_ADDRESS}.pushurl`, PROGRAM],
  [`remote.${MEASURED_ADDRESS}.fetch`, PROGRAM],
  [`remote.${MEASURED_ADDRESS}.tagopt`, PROGRAM],
  [`remote.${MEASURED_ADDRESS}.uploadpack`, PROGRAM],
  ["remote.origin.uploadpack", PROGRAM],
  ["remote.origin.receivepack", PROGRAM],
  ["remote.origin.vcs", PROGRAM],
  ["remote.origin.proxy", PROGRAM],
  ["remote.origin.promisor", PROGRAM],
  ["remote.Other.Name.uploadpack", PROGRAM],
  ["extensions.partialclone", PROGRAM],
  ["fetch.bundleuri", PROGRAM],
  ["http.proactiveauth", PROGRAM],
  ["http.http://127.0.0.1:1/.proactiveauth", PROGRAM],
  ["core.alternaterefscommand", PROGRAM],
  ["core.sshcommand", PROGRAM],
  ["core.gitproxy", PROGRAM],
  ["core.askpass", PROGRAM],
  ["core.editor", PROGRAM],
  ["core.attributesfile", PROGRAM],
  ["sequence.editor", PROGRAM],
  ["gc.recentobjectshook", PROGRAM],
  ["gpg.program", PROGRAM],
  ["gpg.ssh.program", PROGRAM],
  ["gpg.openpgp.program", PROGRAM],
  ["gpg.x509.program", PROGRAM],
  ["gpg.ssh.defaultkeycommand", PROGRAM],
  ["protocol.ext.allow", PROGRAM],
  ["protocol.r2b/../r2bhelper.allow", PROGRAM],
];

const UNLISTED_NAMES = [
  "core.hookspath",
  "credential.helper",
  "core.fsmonitor",
  "safe.barerepository",
  "hook.r2b.event",
  "hook.pre-commit.enabled",
  "maintenance.auto",
  "submodule.recurse",
  "fetch.recursesubmodules",
  "protocol.allow",
  "core.protectntfs",
  "core.protecthfs",
  "filter.f.required",
  "merge.m.name",
  "gpg.format",
  "pull.rebase",
  "commit.gpgsign",
  "merge.verifysignatures",
  "core.worktree",
  "diff.d.textconv",
  "core.pager",
  "user.name",
  "branch.main.rebase",
];

describe("the listing of a repository's own configuration (A7)", () => {
  it("the pattern is one lower-case expression", () => {
    expect(OWN_CONFIG_PATTERN).toBe(PATTERN);
    expect(OWN_CONFIG_PATTERN === OWN_CONFIG_PATTERN.toLowerCase()).toBe(true);
    expect(ownConfigListingArgs()).toEqual([
      "config",
      "-z",
      "--name-only",
      "--get-regexp",
      "--end-of-options",
      PATTERN,
    ]);
  });

  it("the listing's words are a new array each time", () => {
    const first = ownConfigListingArgs();
    first.push("--extra");
    expect(ownConfigListingArgs()).toHaveLength(6);
  });

  it.each(LISTED_NAMES)(
    "every name of the list matches the pattern, read as git prints it: %s",
    (name) => {
      expect(new RegExp(OWN_CONFIG_PATTERN).test(name)).toBe(true);
    },
  );

  it.each(UNLISTED_NAMES)("a key outside the list does not match the pattern: %s", (name) => {
    expect(new RegExp(OWN_CONFIG_PATTERN).test(name)).toBe(false);
  });

  it.each([
    `remotes.${MEASURED_ADDRESS}`,
    `remotes.${ADDRESS}`,
    "remotes.git@h:r.git",
    "remotes.other.git",
    "remotes.default",
  ])("a remote group's key matches the pattern, read as git prints it: %s", (name) => {
    expect(new RegExp(OWN_CONFIG_PATTERN).test(name)).toBe(true);
  });

  it.each(["remotesx.a.git", "xremotes.a.git", "remotes"])(
    "a key that only resembles a remote group's does not match the pattern: %s",
    (name) => {
      expect(new RegExp(OWN_CONFIG_PATTERN).test(name)).toBe(false);
    },
  );
});

describe("the judgement of the listing (A7, G3-4)", () => {
  it.each([
    ["hook.x.command\0", HOOK],
    ["hook..command\0", HOOK],
    ["hook.command\0", PROGRAM],
    ["hook.a.b.command\0", HOOK],
  ] as const)("a hook command is told from the daemon's list: %j", (stdout, judged) => {
    expect(judgeOwnConfig(stdout, ADDRESS)).toEqual(judged);
  });

  it.each(LISTED_NAMES)("every name of the list is a hit: %s", (name, judged) => {
    expect(judgeOwnConfig(`${name}\0`, MEASURED_ADDRESS)).toEqual(judged);
  });

  it("a hook command and a name of the daemon's list in one listing are both told", () => {
    expect(judgeOwnConfig("remote.origin.url\0hook.x.command\0core.sshcommand\0", ADDRESS)).toEqual(
      { hookCommand: true, remoteGroup: false, programOrRewrite: true },
    );
  });

  it.each([
    [ADDRESS, `remotes.${ADDRESS}`, GROUP],
    ["git@h:r.git", "remotes.git@h:r.git", GROUP],
    [ADDRESS, "remotes.default", NO_HIT],
    [ADDRESS, "remotes.other.git", NO_HIT],
    [ADDRESS, "remotes.HTTPS://8.8.8.8/org/repo.git", NO_HIT],
    [ADDRESS, `remotes.${ADDRESS}.git`, NO_HIT],
    [ADDRESS, `remotes.${ADDRESS}/`, NO_HIT],
    [ADDRESS, "remotes.", NO_HIT],
  ] as const)(
    "a remote group named like the address is a hit of its own kind, a group under another name is none: address %s, %s",
    (address, name, judged) => {
      expect(judgeOwnConfig(`${name}\0`, address)).toEqual(judged);
    },
  );

  it("a remote group named like the address leaves the keys beside it what they were", () => {
    expect(
      judgeOwnConfig(
        `remote.r1.url\0remote.r2.url\0remote.r1.fetch\0remotes.${ADDRESS}\0`,
        ADDRESS,
      ),
    ).toEqual(GROUP);
    expect(judgeOwnConfig("remote.origin.url\0remotes.other.git\0", ADDRESS)).toEqual(NO_HIT);
    expect(judgeOwnConfig(`remote.r1.uploadpack\0remotes.${ADDRESS}\0`, ADDRESS)).toEqual({
      hookCommand: false,
      remoteGroup: true,
      programOrRewrite: true,
    });
    expect(judgeOwnConfig(`hook.x.command\0remotes.${ADDRESS}\0`, ADDRESS)).toEqual({
      hookCommand: true,
      remoteGroup: true,
      programOrRewrite: false,
    });
  });

  const SURROGATE_ADDRESS = "https://8.8.8.8/org/\uD800.git";
  const AS_GIT_RECEIVES_IT = "https://8.8.8.8/org/\uFFFD.git";

  it.each([
    ["a remote", `remote.${AS_GIT_RECEIVES_IT}.url`, PROGRAM],
    ["a remote group", `remotes.${AS_GIT_RECEIVES_IT}`, GROUP],
  ] as const)(
    "an address with a lone surrogate is compared as git receives it, U+FFFD in the surrogate's place: %s named so is a hit",
    (_kind, name, judged) => {
      expect(judgeOwnConfig(`${name}\0`, SURROGATE_ADDRESS)).toEqual(judged);
    },
  );

  it("an address with a lone surrogate: a remote and a group named with another character in its place are not the address", () => {
    expect(judgeOwnConfig("remote.https://8.8.8.8/org/x.git.url\0", SURROGATE_ADDRESS)).toEqual(
      NO_HIT,
    );
    expect(judgeOwnConfig("remotes.https://8.8.8.8/org/x.git\0", SURROGATE_ADDRESS)).toEqual(
      NO_HIT,
    );
  });

  it.each([
    [ADDRESS, `remote.${ADDRESS}.url`, PROGRAM],
    [ADDRESS, `remote.${ADDRESS}.fetch`, PROGRAM],
    [ADDRESS, `remote.${ADDRESS}.tagopt`, PROGRAM],
    [ADDRESS, `remote.${ADDRESS}.pushurl`, PROGRAM],
    [ADDRESS, "remote.origin.url", NO_HIT],
    [ADDRESS, "remote.origin.fetch", NO_HIT],
    [ADDRESS, "remote.origin.tagopt", NO_HIT],
    [ADDRESS, "remote.pushdefault", NO_HIT],
    [ADDRESS, "remote.a.b.c.url", NO_HIT],
    [ADDRESS, "remote.origin.uploadpack", PROGRAM],
    [ADDRESS, "remote.origin.receivepack", PROGRAM],
    [ADDRESS, "remote.origin.vcs", PROGRAM],
    [ADDRESS, "remote.origin.proxy", PROGRAM],
    [ADDRESS, "remote.origin.promisor", PROGRAM],
    [ADDRESS, "remote.a.b.uploadpack", PROGRAM],
    [ADDRESS, "remote.HTTPS://8.8.8.8/org/repo.git.url", NO_HIT],
    [ADDRESS, `remote.${ADDRESS}.extra.url`, NO_HIT],
    ["git@h:r.git", "remote.git@h:r.git.url", PROGRAM],
  ] as const)(
    "a remote named like the address is a hit with any key; another remote only with the five: address %s, %s",
    (address, name, judged) => {
      expect(judgeOwnConfig(`${name}\0`, address)).toEqual(judged);
    },
  );

  it.each([
    ["a plain, a shallow, a sparse and a sha256 clone", "remote.origin.url\0remote.origin.fetch\0"],
    [
      "a single-branch and a --no-tags clone",
      "remote.origin.url\0remote.origin.fetch\0remote.origin.tagopt\0",
    ],
    ["a clone with --origin=up", "remote.up.url\0remote.up.fetch\0"],
    ["an empty listing", ""],
  ])("the vault's own clone is no hit: %s", (_clone, stdout) => {
    expect(judgeOwnConfig(stdout, ADDRESS)).toEqual(NO_HIT);
  });
});

describe("what a repository's own configuration can no longer start (A8)", () => {
  it("git's hook events as Documentation/githooks.adoc has them at v2.56.1", () => {
    expect(GIT_HOOK_EVENTS).toEqual(HOOK_EVENTS_AT_V2_56_1);
  });

  it.each(["NUL", "/dev/null"])("the block is the pinned copy: the null device %s", (device) => {
    expect(localStepConfig(device)).toEqual(localStepWords(device));
    expect(localStepConfig(device)).toHaveLength(76);
  });

  const KEPT = {
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/etc/gitconfig",
    GIT_CONFIG_KEY_: "core.sshCommand",
    GIT_CONFIG_KEY_X: "core.sshCommand",
    GIT_TRACE: "1",
    GIT_AUTHOR_NAME: "author",
    HTTPS_PROXY: "http://127.0.0.1:3128",
    PATH: "/usr/bin",
  };

  it.each([
    ...REPOSITORY_VARIABLES,
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_12",
    "git_dir",
    "Git_Config_Count",
    "git_config_key_3",
  ])("git's repository variables are removed, in any letter case: %s", (name) => {
    const env: Record<string, string> = { ...KEPT, [name]: "/elsewhere" };
    const returned = removeRepositoryVariables(env);
    expect(Object.is(returned, env)).toBe(true);
    expect(env).toEqual(KEPT);
  });

  it("the six variables are written over what the allowlist brought", () => {
    const env: Record<string, string> = {
      PATH: "/usr/bin",
      GIT_EDITOR: "vi",
      GIT_ASKPASS: "/x",
      GIT_ALLOW_PROTOCOL: "ext",
    };
    const returned = writeLocalStepVariables(env);
    expect(Object.is(returned, env)).toBe(true);
    const written = Object.fromEntries(
      Object.entries(localEnvironment("/dev/null")).filter(([name]) =>
        LOCAL_STEP_VARIABLES.includes(name),
      ),
    );
    expect(Object.keys(written)).toHaveLength(6);
    expect(env).toEqual({ PATH: "/usr/bin", ...written });
  });
});
