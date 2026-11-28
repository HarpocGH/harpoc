/** The hook events of git's `Documentation/githooks.adoc` at v2.56.1, in the file's order. */
export const GIT_HOOK_EVENTS: readonly string[] = [
  "applypatch-msg",
  "pre-applypatch",
  "post-applypatch",
  "pre-commit",
  "pre-merge-commit",
  "prepare-commit-msg",
  "commit-msg",
  "post-commit",
  "pre-rebase",
  "post-checkout",
  "post-merge",
  "pre-push",
  "pre-receive",
  "update",
  "proc-receive",
  "post-receive",
  "post-update",
  "reference-transaction",
  "push-to-checkout",
  "pre-auto-gc",
  "post-rewrite",
  "sendemail-validate",
  "fsmonitor-watchman",
  "p4-changelist",
  "p4-prepare-changelist",
  "p4-post-changelist",
  "p4-pre-submit",
  "post-index-change",
];

/** The vault's own `core.alternateRefsCommand`, in the relay and on every local step. */
export const NO_ALTERNATE_REFS = ": no alternate refs";

/**
 * A8's `-c` block, behind the forced configuration on the local fetch, the
 * local pull and a clone's local step alone: four of its keys would list
 * themselves in A7's listing.
 */
export function localStepConfig(nullDevice: string): string[] {
  return [
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.file.allow=always",
    "-c",
    "fetch.bundleURI=",
    "-c",
    `core.alternateRefsCommand=${NO_ALTERNATE_REFS}`,
    "-c",
    "submodule.recurse=false",
    "-c",
    "fetch.recurseSubmodules=false",
    "-c",
    "maintenance.auto=false",
    "-c",
    `core.attributesFile=${nullDevice}`,
    "-c",
    "core.protectNTFS=true",
    "-c",
    "core.protectHFS=true",
    ...GIT_HOOK_EVENTS.flatMap((event) => ["-c", `hook.${event}.enabled=false`]),
  ];
}

/** The vault's switches between `fetch` and the caller's arguments: a trailing valued option of the caller cannot take one. */
export const LOCAL_FETCH_SWITCHES = [
  "--no-recurse-submodules",
  "--refmap=",
  "--upload-pack=git-upload-pack",
] as const;

/** The vault's switches between `pull` and the caller's arguments. */
export const LOCAL_PULL_SWITCHES = [
  "--no-recurse-submodules",
  "--upload-pack=git-upload-pack",
] as const;

/**
 * git's `local_repo_env` at v2.32.0 and v2.56.1, the names that name a
 * program or a file for git, and `GIT_REFERENCE_BACKEND` (G3-10, P-3).
 */
const REPOSITORY_VARIABLES = new Set([
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CONFIG",
  "GIT_CONFIG_PARAMETERS",
  "GIT_CONFIG_COUNT",
  "GIT_OBJECT_DIRECTORY",
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_GRAFT_FILE",
  "GIT_INDEX_FILE",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_REPLACE_REF_BASE",
  "GIT_PREFIX",
  "GIT_INTERNAL_SUPER_PREFIX",
  "GIT_SHALLOW_FILE",
  "GIT_COMMON_DIR",
  "GIT_NAMESPACE",
  "GIT_CEILING_DIRECTORIES",
  "GIT_EXEC_PATH",
  "GIT_SSH",
  "GIT_SSH_COMMAND",
  "GIT_EXTERNAL_DIFF",
  "GIT_TEMPLATE_DIR",
  "GIT_ATTR_SOURCE",
  "GIT_REFERENCE_BACKEND",
]);

const NUMBERED_CONFIG_PAIR = /^GIT_CONFIG_(KEY|VALUE)_[0-9]+$/;

/** Deletes git's repository variables from `env`, each name compared in ASCII upper case; returns `env`. */
export function removeRepositoryVariables(env: Record<string, string>): Record<string, string> {
  for (const name of Object.keys(env)) {
    const upper = name.replace(/[a-z]+/g, (letters) => letters.toUpperCase());
    if (REPOSITORY_VARIABLES.has(upper) || NUMBERED_CONFIG_PAIR.test(upper)) {
      Reflect.deleteProperty(env, name);
    }
  }
  return env;
}

/** Writes A8's six variables of the local environment over whatever stands there; returns `env`. */
export function writeLocalStepVariables(env: Record<string, string>): Record<string, string> {
  env.GIT_ALLOW_PROTOCOL = "file";
  env.GIT_ASKPASS = "";
  env.GIT_PROXY_COMMAND = "";
  env.GIT_EDITOR = ":";
  env.GIT_SEQUENCE_EDITOR = ":";
  env.GIT_NO_LAZY_FETCH = "1";
  return env;
}

/**
 * The keys of a repository's own configuration that start a program or
 * redirect the local step (A7), holding no text of the caller. Lower case
 * alone: git lower-cases a pattern only up to its first dot and from its last.
 */
export const OWN_CONFIG_PATTERN =
  "^(hook\\..*\\.command|filter\\..*\\.(smudge|clean|process)|merge\\..*\\.driver|url\\..*\\.(insteadof|pushinsteadof)|remote\\..*|remotes\\..*|extensions\\.partialclone|fetch\\.bundleuri|http\\.(.*\\.)?proactiveauth|core\\.(alternaterefscommand|sshcommand|gitproxy|askpass|editor|attributesfile)|sequence\\.editor|gc\\.recentobjectshook|gpg\\.program|gpg\\..*\\.(program|defaultkeycommand)|protocol\\..*\\.allow)$";

/** The listing's words; with no file option git lists the included files' keys as well. */
export function ownConfigListingArgs(): string[] {
  return ["config", "-z", "--name-only", "--get-regexp", "--end-of-options", OWN_CONFIG_PATTERN];
}

/** The read of every value of the repository's `extensions.refStorage`, each behind a NUL. */
export function refStorageArgs(): string[] {
  return ["config", "-z", "--get-all", "--end-of-options", "extensions.refStorage"];
}

/**
 * The read's answer (`-z`) judged: served where every value is exactly `files`
 * or `reftable`, a format without a path; no value at all is served too.
 */
export function servesRefStorage(stdout: string): boolean {
  const values = stdout.split("\0");
  return values.pop() === "" && values.every((value) => value === "files" || value === "reftable");
}

const REMOTE_PROGRAM_VARIABLES = new Set(["uploadpack", "receivepack", "vcs", "proxy", "promisor"]);

function isHookCommand(name: string): boolean {
  return (
    name.startsWith("hook.") && name.endsWith(".command") && name.length > "hook.command".length
  );
}

/**
 * A remote's key that neither starts a program nor redirects the local step:
 * one without a subsection, or one of a remote not named exactly `repository`
 * whose variable names no program.
 */
function isHarmlessRemoteKey(name: string, repository: string): boolean {
  if (!name.startsWith("remote.")) return false;
  const first = name.indexOf(".");
  const last = name.lastIndexOf(".");
  if (first === last) return true;
  return (
    name.slice(first + 1, last) !== repository &&
    !REMOTE_PROGRAM_VARIABLES.has(name.slice(last + 1))
  );
}

const REMOTE_GROUP_PREFIX = "remotes.";

/**
 * The listing's answer (`-z --name-only`) read: a hook defined in `config` and
 * a remote group named exactly `repository`, each refused in both models, told
 * from the other names the pattern listed, which a daemon refuses; a remote
 * group under another name is no hit. `repository` is compared as git receives
 * it, an unpaired surrogate as U+FFFD.
 */
export function judgeOwnConfig(
  stdout: string,
  repository: string,
): { hookCommand: boolean; remoteGroup: boolean; programOrRewrite: boolean } {
  const address = Buffer.from(repository, "utf8").toString("utf8");
  let hookCommand = false;
  let remoteGroup = false;
  let programOrRewrite = false;
  for (const name of stdout.split("\0")) {
    if (name === "") continue;
    if (isHookCommand(name)) hookCommand = true;
    else if (name.startsWith(REMOTE_GROUP_PREFIX)) {
      if (name.slice(REMOTE_GROUP_PREFIX.length) === address) remoteGroup = true;
    } else if (!isHarmlessRemoteKey(name, address)) programOrRewrite = true;
  }
  return { hookCommand, remoteGroup, programOrRewrite };
}
