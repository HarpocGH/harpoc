import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { VaultError } from "@harpoc/shared";

/**
 * Network isolation for process-mediated spawns (thesis §4.5.3 layer 4).
 *
 * A secret whose injection policy demands `network_isolation` must never put
 * the credential into a child that can reach the network. The mechanism is a
 * vault-authored argv prefix applied at the `spawnCaptured` seam AFTER
 * allowlist resolution — the pinned resolved path stays the audited command,
 * and no agent input ever reaches the prefix:
 *
 *  - Linux:  `unshare -rn -- <command> <args...>` — a new user + network
 *    namespace (unprivileged on modern kernels); `lo` stays down, so even
 *    loopback is unreachable. `-r` maps the caller to root inside the userns
 *    so `getpwuid`/DAC behave for children like `ssh` that stat their files.
 *  - macOS:  `sandbox-exec -p '<deny-network profile>' <command> <args...>` —
 *    deprecated by Apple but functional; availability is probed live, never
 *    assumed, so a future removal fails closed.
 *  - Windows and everything else: unavailable by design (AppContainers would
 *    require a native addon) — the policy-demanding use is refused.
 *
 * Wrapper binaries resolve from pinned absolute candidate paths only, never
 * PATH (the keystore-bridge doctrine). Capability is a live probe — a wrapper
 * binary can be present yet blocked (kernel.unprivileged_userns_clone=0,
 * AppArmor userns restrictions) — cached per process; environment drift after
 * a passing probe still fails closed by construction, because the wrapper
 * errors out without exec-ing the payload.
 */

export type NetworkIsolationMechanism = "unshare" | "sandbox-exec";

export interface NetworkIsolationWrap {
  /** The pinned wrapper binary (absolute path). */
  command: string;
  /** Vault-authored prefix args followed by the resolved command and its args. */
  args: string[];
  mechanism: NetworkIsolationMechanism;
}

/** Injectable seams for unit tests; production callers pass nothing. */
export interface NetworkIsolationSeams {
  platform?: NodeJS.Platform;
  probeBinary?: (path: string) => boolean;
  runProbe?: (command: string, args: string[]) => Promise<boolean>;
}

/**
 * Minimal deny-network sandbox profile (macOS). A single constant passed as
 * one argv element — never interpolated, so no injection surface.
 * `(deny network*)` covers outbound, inbound, bind and loopback.
 */
export const SANDBOX_EXEC_DENY_NETWORK_PROFILE = "(version 1)(allow default)(deny network*)";

const LINUX_UNSHARE_CANDIDATES = ["/usr/bin/unshare", "/bin/unshare"];
const POSIX_TRUE_CANDIDATES = ["/usr/bin/true", "/bin/true"];
const DARWIN_SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const PROBE_TIMEOUT_MS = 5_000;

interface ResolvedIsolation {
  wrapper: string;
  prefixArgs: string[];
  mechanism: NetworkIsolationMechanism;
}

function findPinnedBinary(candidates: string[], probe: (path: string) => boolean): string | null {
  for (const candidate of candidates) {
    if (probe(candidate)) return candidate;
  }
  return null;
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

async function resolveIsolation(seams?: NetworkIsolationSeams): Promise<ResolvedIsolation> {
  const platform = seams?.platform ?? process.platform;
  const probeBinary = seams?.probeBinary ?? existsSync;
  const runProbe = seams?.runProbe ?? runProbeDefault;

  if (platform === "linux") {
    const unshare = findPinnedBinary(LINUX_UNSHARE_CANDIDATES, probeBinary);
    if (!unshare) {
      throw VaultError.networkIsolationUnavailable("unshare not found in /usr/bin or /bin");
    }
    const trueBin = findPinnedBinary(POSIX_TRUE_CANDIDATES, probeBinary);
    if (!trueBin) {
      throw VaultError.networkIsolationUnavailable(
        "no /usr/bin/true or /bin/true available for the capability probe",
      );
    }
    if (!(await runProbe(unshare, ["-rn", "--", trueBin]))) {
      throw VaultError.networkIsolationUnavailable(
        "unprivileged user namespaces unavailable (unshare -rn probe failed)",
      );
    }
    return { wrapper: unshare, prefixArgs: ["-rn", "--"], mechanism: "unshare" };
  }

  if (platform === "darwin") {
    if (!probeBinary(DARWIN_SANDBOX_EXEC)) {
      throw VaultError.networkIsolationUnavailable(
        `sandbox-exec not found at ${DARWIN_SANDBOX_EXEC}`,
      );
    }
    const trueBin = findPinnedBinary(POSIX_TRUE_CANDIDATES, probeBinary);
    if (!trueBin) {
      throw VaultError.networkIsolationUnavailable(
        "no /usr/bin/true or /bin/true available for the capability probe",
      );
    }
    if (
      !(await runProbe(DARWIN_SANDBOX_EXEC, ["-p", SANDBOX_EXEC_DENY_NETWORK_PROFILE, trueBin]))
    ) {
      throw VaultError.networkIsolationUnavailable("sandbox-exec deny-network probe failed");
    }
    return {
      wrapper: DARWIN_SANDBOX_EXEC,
      prefixArgs: ["-p", SANDBOX_EXEC_DENY_NETWORK_PROFILE],
      mechanism: "sandbox-exec",
    };
  }

  throw VaultError.networkIsolationUnavailable(`unsupported platform: ${platform}`);
}

/**
 * The resolution (capability probe included) is cached for the process
 * lifetime — a rejected resolution is cached too, since platform capability
 * does not change under the vault. Tests reset via the hook below; the cache
 * captures the first caller's seams, so tests must reset between seam configs.
 */
let cachedResolution: Promise<ResolvedIsolation> | null = null;
let forcedUnavailableForTests: string | null = null;

/**
 * Wrap an already-resolved command in the platform's network-isolation prefix,
 * or throw `NETWORK_ISOLATION_UNAVAILABLE` (fail closed — a policy-demanding
 * spawn must never proceed un-isolated).
 */
export async function requireNetworkIsolation(
  command: string,
  args: string[],
  seams?: NetworkIsolationSeams,
): Promise<NetworkIsolationWrap> {
  if (forcedUnavailableForTests !== null) {
    throw VaultError.networkIsolationUnavailable(forcedUnavailableForTests);
  }
  cachedResolution ??= resolveIsolation(seams);
  const resolved = await cachedResolution;
  return {
    command: resolved.wrapper,
    args: [...resolved.prefixArgs, command, ...args],
    mechanism: resolved.mechanism,
  };
}

export function resetNetworkIsolationProbeForTests(): void {
  cachedResolution = null;
}

/**
 * Force refusal regardless of platform — integration tests exercise the real
 * fail-closed path on hosts where the probe would succeed. Only unavailability
 * can be forced (tightening); there is no way to force "available".
 */
export function forceNetworkIsolationUnavailableForTests(reason: string | null): void {
  forcedUnavailableForTests = reason;
}
