import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { VaultError } from "@harpoc/shared";

/**
 * Filesystem isolation for process-mediated spawns (thesis §4.5.3 layer 4).
 *
 * A secret whose injection policy demands `fs_isolation` must never put the
 * credential into a child that can write to the filesystem — the child may
 * read what it needs to run, but it cannot persist the credential, drop a
 * payload, or tamper with the vault's own files. The mechanism is a
 * vault-authored argv prefix applied at the `spawnCaptured` seam AFTER
 * allowlist resolution — the pinned resolved path stays the audited command,
 * and no agent input ever reaches the prefix:
 *
 *  - Linux:  `setpriv --landlock-access fs --landlock-rule <read rule>
 *    --landlock-rule <write rule> -- <command> <args...>` — a Landlock LSM
 *    ruleset applied to the child and inherited by its descendants; it is a
 *    one-way restriction no child can drop. Execute/read stays open across
 *    `/` so the payload can run; the only write-file grant is `/dev/null`
 *    (Landlock needs at least one rule per handled access class, and a
 *    write-anywhere-else child would defeat the point). Needs util-linux
 *    >= 2.40 for the `--landlock-*` options and a Landlock-enabled kernel.
 *  - macOS:  `sandbox-exec -p '<deny-write profile>' <command> <args...>` —
 *    deprecated by Apple but functional; availability is probed live, never
 *    assumed, so a future removal fails closed.
 *  - Windows and everything else: unavailable by design (a job-object /
 *    AppContainer equivalent would require a native addon) — the
 *    policy-demanding use is refused.
 *
 * When a secret demands network AND filesystem isolation at once, macOS can
 * express both in a SINGLE sandbox profile — see `requireCombinedIsolation`,
 * which lives here because it shares this module's probe machinery. Linux has
 * no single wrapper for both and composes `unshare` around `setpriv` at the
 * spawn seam instead.
 *
 * Wrapper binaries resolve from pinned absolute candidate paths only, never
 * PATH (the keystore-bridge doctrine). Capability is a live probe — a wrapper
 * binary can be present yet blocked (kernel without CONFIG_SECURITY_LANDLOCK,
 * a util-linux too old to know `--landlock-access`) — cached per process;
 * environment drift after a passing probe still fails closed by construction,
 * because the wrapper errors out without exec-ing the payload.
 */

export type FsIsolationMechanism = "landlock" | "sandbox-exec";

export interface FsIsolationWrap {
  /** The pinned wrapper binary (absolute path). */
  command: string;
  /** Vault-authored prefix args followed by the resolved command and its args. */
  args: string[];
  mechanism: FsIsolationMechanism;
}

/** Injectable seams for unit tests; production callers pass nothing. */
export interface FsIsolationSeams {
  platform?: NodeJS.Platform;
  probeBinary?: (path: string) => boolean;
  runProbe?: (command: string, args: string[]) => Promise<boolean>;
}

/**
 * The Landlock ruleset, one argv token per array element — never joined into
 * a string, so there is no quoting or splitting surface. Read/execute is
 * granted across `/` (the payload must be able to run and read its libraries);
 * the sole write grant is `/dev/null`, which Landlock requires because a
 * handled access class with no rule at all is rejected by setpriv.
 * The trailing `--` is load-bearing: without it a payload whose first arg
 * starts with `-` would be parsed as a setpriv option.
 */
export const LANDLOCK_PREFIX_ARGS = [
  "--landlock-access",
  "fs",
  "--landlock-rule",
  "path-beneath:execute,read-file,read-dir:/",
  "--landlock-rule",
  "path-beneath:write-file:/dev/null",
  "--",
] as const;

/**
 * Minimal deny-write sandbox profile (macOS). A single constant passed as
 * one argv element — never interpolated, so no injection surface.
 * `(deny file-write*)` covers create, write, unlink, rename and chmod.
 */
export const SANDBOX_EXEC_DENY_WRITE_PROFILE = "(version 1)(allow default)(deny file-write*)";

/**
 * Combined deny-network + deny-write sandbox profile (macOS). A single
 * constant passed as one argv element — never interpolated, so no injection
 * surface. macOS expresses both demands in ONE wrapper; nesting two
 * `sandbox-exec` invocations is not supported, hence this third profile
 * rather than a composition of the other two.
 */
export const SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE =
  "(version 1)(allow default)(deny network*)(deny file-write*)";

/** Pinned absolute candidates for the Linux wrapper — PATH is never consulted. */
export const LINUX_SETPRIV_CANDIDATES = ["/usr/bin/setpriv", "/bin/setpriv"] as const;

const POSIX_TRUE_CANDIDATES = ["/usr/bin/true", "/bin/true"];
const DARWIN_SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const PROBE_TIMEOUT_MS = 5_000;

interface ResolvedIsolation {
  wrapper: string;
  prefixArgs: string[];
  mechanism: FsIsolationMechanism;
}

function findPinnedBinary(
  candidates: readonly string[],
  probe: (path: string) => boolean,
): string | null {
  for (const candidate of candidates) {
    if (probe(candidate)) return candidate;
  }
  return null;
}

/** The no-op payload every capability probe execs; refusal is fail-closed. */
function requireProbePayload(probeBinary: (path: string) => boolean): string {
  const trueBin = findPinnedBinary(POSIX_TRUE_CANDIDATES, probeBinary);
  if (!trueBin) {
    throw VaultError.fsIsolationUnavailable(
      "no /usr/bin/true or /bin/true available for the capability probe",
    );
  }
  return trueBin;
}

/** Run a capability probe: exit 0 within the timeout means available. */
function runProbeDefault(command: string, args: string[]): Promise<boolean> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, { shell: false, stdio: "ignore", windowsHide: true });
    } catch {
      resolve(false);
      return;
    }
    const timer = setTimeout(() => child.kill("SIGKILL"), PROBE_TIMEOUT_MS);
    if (timer.unref) timer.unref();
    child.on("error", () => {
      clearTimeout(timer);
      resolve(false);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve(code === 0);
    });
  });
}

async function resolveFsIsolation(seams?: FsIsolationSeams): Promise<ResolvedIsolation> {
  const platform = seams?.platform ?? process.platform;
  const probeBinary = seams?.probeBinary ?? existsSync;
  const runProbe = seams?.runProbe ?? runProbeDefault;

  if (platform === "linux") {
    const setpriv = findPinnedBinary(LINUX_SETPRIV_CANDIDATES, probeBinary);
    if (!setpriv) {
      throw VaultError.fsIsolationUnavailable("setpriv not found in /usr/bin or /bin");
    }
    const trueBin = requireProbePayload(probeBinary);
    if (!(await runProbe(setpriv, [...LANDLOCK_PREFIX_ARGS, trueBin]))) {
      throw VaultError.fsIsolationUnavailable(
        "Landlock unavailable (setpriv --landlock-access probe failed; needs util-linux >= 2.40 on a Landlock-enabled kernel)",
      );
    }
    return { wrapper: setpriv, prefixArgs: [...LANDLOCK_PREFIX_ARGS], mechanism: "landlock" };
  }

  if (platform === "darwin") {
    if (!probeBinary(DARWIN_SANDBOX_EXEC)) {
      throw VaultError.fsIsolationUnavailable(`sandbox-exec not found at ${DARWIN_SANDBOX_EXEC}`);
    }
    const trueBin = requireProbePayload(probeBinary);
    if (!(await runProbe(DARWIN_SANDBOX_EXEC, ["-p", SANDBOX_EXEC_DENY_WRITE_PROFILE, trueBin]))) {
      throw VaultError.fsIsolationUnavailable("sandbox-exec deny-write probe failed");
    }
    return {
      wrapper: DARWIN_SANDBOX_EXEC,
      prefixArgs: ["-p", SANDBOX_EXEC_DENY_WRITE_PROFILE],
      mechanism: "sandbox-exec",
    };
  }

  throw VaultError.fsIsolationUnavailable(`unsupported platform: ${platform}`);
}

async function resolveCombinedIsolation(seams?: FsIsolationSeams): Promise<ResolvedIsolation> {
  const platform = seams?.platform ?? process.platform;
  const probeBinary = seams?.probeBinary ?? existsSync;
  const runProbe = seams?.runProbe ?? runProbeDefault;

  if (platform !== "darwin") {
    throw VaultError.fsIsolationUnavailable(
      platform === "linux"
        ? "combined network+filesystem isolation is composed from unshare + setpriv on linux, not a single wrapper"
        : `unsupported platform: ${platform}`,
    );
  }
  if (!probeBinary(DARWIN_SANDBOX_EXEC)) {
    throw VaultError.fsIsolationUnavailable(`sandbox-exec not found at ${DARWIN_SANDBOX_EXEC}`);
  }
  const trueBin = requireProbePayload(probeBinary);
  if (
    !(await runProbe(DARWIN_SANDBOX_EXEC, [
      "-p",
      SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE,
      trueBin,
    ]))
  ) {
    throw VaultError.fsIsolationUnavailable("sandbox-exec deny-network+deny-write probe failed");
  }
  return {
    wrapper: DARWIN_SANDBOX_EXEC,
    prefixArgs: ["-p", SANDBOX_EXEC_DENY_NETWORK_AND_WRITE_PROFILE],
    mechanism: "sandbox-exec",
  };
}

/**
 * A successful resolution (capability probe included) is cached for the
 * process lifetime — genuine platform capability does not change under the
 * vault. A REJECTED resolution is deliberately NOT cached: a probe can fail
 * transiently (5 s timeout under load, fork pressure), and caching that
 * would permanently disable every isolation-demanding spawn in a long-lived
 * server. Re-probing on genuinely incapable hosts is cheap (setpriv exits
 * non-zero immediately; unsupported platforms throw before probing).
 * Concurrent callers still coalesce on the in-flight promise. The two
 * mechanisms keep SEPARATE slots — a host may run `sandbox-exec` with the
 * deny-write profile yet reject the combined one — so neither probe's result
 * ever stands in for the other's. Tests reset via the hook below; a cache
 * captures the first caller's seams, so tests must reset between seam
 * configs.
 */
let cachedFsResolution: Promise<ResolvedIsolation> | null = null;
let cachedCombinedResolution: Promise<ResolvedIsolation> | null = null;
let forcedUnavailableForTests: string | null = null;

/** Single-slot only-success cache with self-clearing rejection (see above). */
function resolveCached(
  read: () => Promise<ResolvedIsolation> | null,
  write: (slot: Promise<ResolvedIsolation> | null) => void,
  resolve: () => Promise<ResolvedIsolation>,
): Promise<ResolvedIsolation> {
  const cached = read();
  if (cached) return cached;
  const attempt: Promise<ResolvedIsolation> = resolve().catch((err: unknown) => {
    // Only success is cached — a rejection may be load, not capability.
    if (read() === attempt) write(null);
    throw err;
  });
  write(attempt);
  return attempt;
}

/**
 * Wrap an already-resolved command in the platform's filesystem-isolation
 * prefix, or throw `FS_ISOLATION_UNAVAILABLE` (fail closed — a
 * policy-demanding spawn must never proceed un-isolated).
 */
export async function requireFsIsolation(
  command: string,
  args: readonly string[],
  seams?: FsIsolationSeams,
): Promise<FsIsolationWrap> {
  if (forcedUnavailableForTests !== null) {
    throw VaultError.fsIsolationUnavailable(forcedUnavailableForTests);
  }
  const resolved = await resolveCached(
    () => cachedFsResolution,
    (slot) => {
      cachedFsResolution = slot;
    },
    () => resolveFsIsolation(seams),
  );
  return {
    command: resolved.wrapper,
    args: [...resolved.prefixArgs, command, ...args],
    mechanism: resolved.mechanism,
  };
}

/**
 * Wrap an already-resolved command in ONE macOS sandbox that denies network
 * AND filesystem writes, for a secret demanding both isolations. darwin-only:
 * Linux has no equivalent single wrapper and composes `unshare` around
 * `setpriv` at the spawn seam instead, so this refuses there (and everywhere
 * else) rather than silently delivering half the demand.
 */
export async function requireCombinedIsolation(
  command: string,
  args: readonly string[],
  seams?: FsIsolationSeams,
): Promise<FsIsolationWrap> {
  if (forcedUnavailableForTests !== null) {
    throw VaultError.fsIsolationUnavailable(forcedUnavailableForTests);
  }
  const resolved = await resolveCached(
    () => cachedCombinedResolution,
    (slot) => {
      cachedCombinedResolution = slot;
    },
    () => resolveCombinedIsolation(seams),
  );
  return {
    command: resolved.wrapper,
    args: [...resolved.prefixArgs, command, ...args],
    mechanism: resolved.mechanism,
  };
}

export function resetFsIsolationProbeForTests(): void {
  cachedFsResolution = null;
  cachedCombinedResolution = null;
}

/**
 * Force refusal regardless of platform — integration tests exercise the real
 * fail-closed path on hosts where the probe would succeed. Only unavailability
 * can be forced (tightening); there is no way to force "available".
 */
export function forceFsIsolationUnavailableForTests(reason: string | null): void {
  forcedUnavailableForTests = reason;
}
