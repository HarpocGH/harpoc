import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import type { DockerRegistryAction, DockerResult, InjectionPolicy } from "@harpoc/shared";
import { ErrorCode, MIN_REDACTABLE_FRAGMENT, VaultError } from "@harpoc/shared";
import { controlledPathDirs, matchesHostAllowlist, resolveAndMatchCommand } from "../allowlist.js";
import { redactErrorMessage } from "../output-sanitizer.js";
import { spawnCaptured } from "../spawn-captured.js";
import type { SpawnCapturedResult } from "../spawn-captured.js";

/**
 * The bundled docker credential helper (design §5.4). Docker resolves it as
 * `docker-credential-harpoc` on PATH (named by the `credHelpers` entry the
 * vault writes into DOCKER_CONFIG/config.json) and invokes it per the
 * credential-helper protocol: argv is `[helper, <action>]`, and for `get` the
 * requested server URL arrives on stdin.
 *
 * The credential never reaches docker on argv or through a stored config: it
 * lives only in this helper's environment (`HARPOC_DOCKER_*`), served on demand
 * and only for the one registry the vault bound it to.
 *
 * Security posture:
 *  - `get` for the bound host (`HARPOC_DOCKER_REGISTRY`, case-insensitive) →
 *    the exact credential JSON, exit 0.
 *  - `get` for ANY other host → docker's recognized "no credentials" signal on
 *    stdout, exit 1, and NOT one byte of the secret. A pull that redirected to
 *    a foreign registry therefore gets anonymous access, never the credential.
 *  - `store`/`erase`/`list` → exit 1 before touching stdin: the vault-authored
 *    helper is read-only and never persists a credential.
 *
 * The literal `\n` sequences are written into the emitted `.mjs`, not
 * interpreted here (mirrors git-injector's ASKPASS_HELPER_SRC).
 */
export const DOCKER_CREDENTIAL_HELPER_SRC = `import { readFileSync } from "node:fs";

const action = process.argv[2] || "";
if (action !== "get") {
  // store / erase / list: read-only helper, never persists or lists — exit
  // before reading stdin so a credential can never be captured off it.
  process.stderr.write("harpoc: credential-helper operation not supported\\n");
  process.exit(1);
}

const expected = (process.env.HARPOC_DOCKER_REGISTRY || "").trim().toLowerCase();
let requested = "";
try {
  requested = readFileSync(0, "utf8").trim().toLowerCase();
} catch {
  requested = "";
}

if (!expected || requested !== expected) {
  // docker's recognized "no credentials" signal — printed to stdout, exit 1.
  // Emphatically NOT the credential: a host the vault did not bind gets nothing.
  process.stdout.write("credentials not found in native keychain\\n");
  process.exit(1);
}

const out = JSON.stringify({
  Username: process.env.HARPOC_DOCKER_USER || "",
  Secret: process.env.HARPOC_DOCKER_SECRET || "",
  ServerURL: process.env.HARPOC_DOCKER_REGISTRY || "",
});
process.stdout.write(out + "\\n");
`;

/**
 * Metadata-only audit projection of a docker-registry operation (spec §7.2) —
 * never a credential. Every field the builder writes is request-derived (the
 * registry is parsed from the image reference), so the same projection covers
 * both a successful use and a denial, exactly like the SFTP context. The
 * optional `sanitized` is the one result-derived key: the engine folds it onto
 * whichever row the spawn produced — a success, or a graceful non-throwing
 * failure such as PROCESS_TIMEOUT — never onto a refusal row, which never
 * reached a spawn.
 */
export interface DockerAuditDetails {
  registry: string;
  image: string;
  operation: string;
  /** Present only when the credential redaction changed the captured output (E70). */
  sanitized?: true;
}

/**
 * The docker executor's return to the engine: the wire result plus whether the
 * spawn seam's redaction changed the captured output. `sanitized` rides the
 * engine's post-spawn audit row only — {@link DockerResult} stays byte-identical.
 */
export interface DockerExecution {
  result: DockerResult;
  sanitized: boolean;
}

/** Builds the metadata-only audit projection for a docker action. Pure — the
 * engine calls it for both success and failed `secret.use` rows. */
export function buildDockerAuditDetails(action: DockerRegistryAction): DockerAuditDetails {
  return {
    registry: parseImageReference(action.image).registry,
    image: action.image,
    operation: action.operation,
  };
}

/** The default registry docker itself resolves a registry-less reference to. */
const DEFAULT_REGISTRY = "registry-1.docker.io";

/**
 * Split an image reference `[registry-host[:port]/]repo[:tag][@digest]` into its
 * registry authority and repository. The registry component is the allowlist
 * subject and the `credHelpers` key. When the reference carries no registry
 * host — a bare `nginx:latest` or a Docker Hub `user/repo` — the registry
 * defaults to {@link DEFAULT_REGISTRY}; that default host must still be present
 * in `host_allowlist` (fail-safe deny — a bare image is not implicitly trusted).
 *
 * The first path segment is a registry host only when it looks like one: it
 * contains a `.` (domain) or `:` (port), or is exactly `localhost`. Otherwise
 * it is a Docker Hub namespace, and the whole reference is the repository — the
 * same rule the docker CLI applies.
 */
export function parseImageReference(image: string): { registry: string; repository: string } {
  const firstSlash = image.indexOf("/");
  if (firstSlash === -1) {
    return { registry: DEFAULT_REGISTRY, repository: image };
  }
  const first = image.slice(0, firstSlash);
  if (first.includes(".") || first.includes(":") || first === "localhost") {
    return { registry: first, repository: image.slice(firstSlash + 1) };
  }
  return { registry: DEFAULT_REGISTRY, repository: image };
}

/** Parse the `username:password` registry credential from the secret value. */
function parseDockerCredential(value: Uint8Array): { user: string; secret: string } {
  const s = Buffer.from(value).toString("utf8");
  const i = s.indexOf(":");
  if (i < 0) return { user: "", secret: s };
  return { user: s.slice(0, i), secret: s.slice(i + 1) };
}

/** A private DOCKER_CONFIG dir holding only the vault-authored config.json. */
function writeDockerConfig(registry: string): { dir: string; dispose: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-docker-config-"));
  // The golden config — exactly a `credHelpers` entry pointing docker at our
  // helper, and NEVER an `auths` key (which would embed a base64 credential in
  // the file). `DOCKER_CONFIG` overrides the user's real ~/.docker/config.json,
  // so docker reads only this.
  const config = JSON.stringify({ credHelpers: { [registry]: "harpoc" } });
  writeFileSync(join(dir, "config.json"), config, { mode: 0o600 });
  return { dir, dispose: () => disposeDir(dir) };
}

/**
 * A private dir holding the credential-helper launcher docker resolves by name
 * (`docker-credential-harpoc`), plus the embedded `.mjs` it execs. Mirrors
 * git-injector's `writeAskpass`: a `.cmd` launcher on win32, a `sh` launcher
 * otherwise, both exec `node <helper.mjs>`. The credential is passed to the
 * helper via env, never argv.
 */
function writeCredentialHelper(): { dir: string; dispose: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-docker-helper-"));
  const helper = join(dir, "docker-credential-harpoc.mjs");
  writeFileSync(helper, DOCKER_CREDENTIAL_HELPER_SRC, { mode: 0o700 });
  const node = process.execPath;
  if (process.platform === "win32") {
    const launcher = join(dir, "docker-credential-harpoc.cmd");
    writeFileSync(launcher, `@"${node}" "${helper}" %*\r\n`, { mode: 0o700 });
  } else {
    const launcher = join(dir, "docker-credential-harpoc");
    writeFileSync(launcher, `#!/bin/sh\nexec "${node}" "${helper}" "$@"\n`, { mode: 0o700 });
  }
  return { dir, dispose: () => disposeDir(dir) };
}

function disposeDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

/** Clean base environment for the spawned docker process. */
function baseDockerEnv(envAllowlist: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  const path = process.env.PATH ?? process.env.Path;
  if (path) env.PATH = path;
  if (process.platform === "win32" && process.env.SystemRoot) {
    env.SystemRoot = process.env.SystemRoot;
  }
  for (const name of envAllowlist) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  return env;
}

/**
 * Map a settled spawn result to the process-shaped {@link DockerResult}, or
 * throw for the outcomes the vault treats as a hard failure rather than a
 * return value: a spawn failure, or any non-zero exit — `docker pull`/`push`
 * report the operation as failed via a non-zero status, so the vault surfaces
 * it as {@link ErrorCode.DOCKER_OPERATION_FAILED}. A timeout returns gracefully
 * (mirrors sftp/git) so the caller can distinguish it.
 */
function toDockerResult(action: DockerRegistryAction, r: SpawnCapturedResult): DockerResult {
  if (r.spawn_failed) {
    throw VaultError.dockerOperationFailed(r.exit_code ?? -1);
  }
  if (r.timed_out) {
    return {
      type: "docker_registry",
      operation: action.operation,
      exit_code: r.exit_code,
      stdout: r.stdout,
      stderr: r.stderr,
      timed_out: true,
      truncated: r.truncated ? true : undefined,
      signal: r.signal ?? undefined,
      error: ErrorCode.PROCESS_TIMEOUT,
    };
  }
  if (r.exit_code !== 0) {
    throw VaultError.dockerOperationFailed(r.exit_code ?? -1);
  }
  return {
    type: "docker_registry",
    operation: action.operation,
    exit_code: r.exit_code,
    stdout: r.stdout,
    stderr: r.stderr,
    timed_out: undefined,
    truncated: r.truncated ? true : undefined,
    signal: r.signal ?? undefined,
    error: undefined,
  };
}

/**
 * Executes a Docker registry pull/push, authenticating through a vault-authored
 * credential helper (design §5.4). The vault spawns the real `docker` CLI;
 * the credential is served to it only for the one registry the image resolves
 * to, via `docker-credential-harpoc`, and never appears on argv, in a stored
 * config, or in the captured output.
 *
 * Security controls realized here:
 *  - Registry host allowlist — fail-safe deny (process-mediated posture); the
 *    default Docker Hub host counts and must be allowlisted for a bare image.
 *  - Command allowlist: the docker binary is pinned to a resolved absolute path.
 *  - The private `DOCKER_CONFIG` carries ONLY a `credHelpers` entry — never an
 *    `auths` credential — so docker reads no ambient credentials and defers to
 *    the helper, which binds the credential to the validated registry.
 *  - Both temp dirs are disposed in `finally`, including every throw path.
 *
 * Isolation is deliberately NOT wired here: a `docker_registry` action on a
 * secret demanding network/fs isolation is refused at the engine BEFORE
 * dispatch (design §5.4 — the daemon, not the spawned CLI, performs the egress
 * and writes the layers), so this injector never runs under isolation.
 */
export async function executeDockerRegistryAction(
  action: DockerRegistryAction,
  secretValue: Uint8Array,
  policy: InjectionPolicy,
): Promise<DockerExecution> {
  const { user, secret } = parseDockerCredential(secretValue);
  try {
    return await runDocker(action, policy, user, secret);
  } catch (rawErr) {
    // Every throw out of the injector passes redactErrorMessage: a thrown
    // message is a model-visible channel no result-shaped redaction touches.
    throw redactErrorMessage(rawErr, secret);
  }
}

async function runDocker(
  action: DockerRegistryAction,
  policy: InjectionPolicy,
  user: string,
  secret: string,
): Promise<DockerExecution> {
  // Defense in depth beside the schema's alphanumeric-anchored image regex: the
  // image reaches argv, so a leading dash must never parse as a docker flag.
  if (action.image.startsWith("-")) {
    throw VaultError.invalidInput("docker image reference must not start with '-'");
  }

  const { registry } = parseImageReference(action.image);

  // Registry host allowlist — fail-safe deny (process-mediated posture). The
  // default Docker Hub host is not exempt.
  if (
    policy.host_allowlist.length === 0 ||
    !matchesHostAllowlist(registry, policy.host_allowlist)
  ) {
    throw VaultError.hostNotAllowed(registry);
  }

  // Resolve + allowlist the docker binary (fail-safe deny, absolute-path pinned).
  const dockerPath = resolveAndMatchCommand(
    "docker",
    policy.command_allowlist,
    controlledPathDirs(),
  );

  const config = writeDockerConfig(registry);
  // The helper is created INSIDE the try so `config.dispose()` still runs if
  // `writeCredentialHelper()` throws (mkdtemp/writeFile failure) — otherwise the
  // credential-free config tmpdir would leak on that pre-try throw path.
  let helper: { dir: string; dispose: () => void } | undefined;
  try {
    helper = writeCredentialHelper();
    const env = baseDockerEnv(policy.env_allowlist);
    env.DOCKER_CONFIG = config.dir;
    // Prepend the helper dir so docker resolves docker-credential-harpoc there.
    env.PATH = helper.dir + delimiter + (env.PATH ?? "");
    env.HARPOC_DOCKER_REGISTRY = registry;
    env.HARPOC_DOCKER_USER = user;
    env.HARPOC_DOCKER_SECRET = secret;

    // The username is credential material too, down to the shared floor
    // (MIN_REDACTABLE_FRAGMENT); shorter fragments stay unredacted (mirrors git).
    const redact = user.length >= MIN_REDACTABLE_FRAGMENT ? [secret, user] : [secret];

    const r = await spawnCaptured(dockerPath, [action.operation, action.image], {
      env,
      timeoutMs: action.timeout_ms,
      redact,
    });
    return { result: toDockerResult(action, r), sanitized: r.redacted };
  } finally {
    config.dispose();
    helper?.dispose();
  }
}
