import type { FsIsolationMechanism } from "./fs-isolation.js";
import { requireCombinedIsolation, requireFsIsolation } from "./fs-isolation.js";
import type { NetworkIsolationMechanism } from "./network-isolation.js";
import { requireNetworkIsolation } from "./network-isolation.js";

/**
 * Isolation composer for process-mediated spawns (thesis §4.5.3 layer 4).
 *
 * A secret's injection policy can demand network isolation, filesystem
 * isolation, or both. Each dimension has its own platform resolver; this
 * module is the one place that turns a pair of demands into a single wrapped
 * argv, so the `spawnCaptured` seam stays a straight-line call and no context
 * can compose the wrappers differently:
 *
 *  - network only → `requireNetworkIsolation`, argv unchanged from the
 *    single-dimension era (byte-identical: the pinned tests hold).
 *  - fs only → `requireFsIsolation`.
 *  - both, linux → the fs wrap is built FIRST and the network wrap goes
 *    AROUND it when both primaries resolved:
 *    `unshare -rn -- setpriv <landlock args> -- <payload>`. The order is
 *    load-bearing in both directions: `unshare` must create the namespaces
 *    before Landlock restricts the process (a Landlock ruleset is inherited
 *    and irrevocable, and `unshare -r` still needs to write the uid/gid
 *    maps), and the payload stays last and unmodified either way. When either
 *    dimension fell to the second tier, ONE bwrap wrapper carries both
 *    (`requireCombinedIsolation`'s linux branch) — bwrap is never nested
 *    inside `unshare`, nor `setpriv` inside bwrap.
 *  - both, darwin → ONE `sandbox-exec` wrapper carrying the combined
 *    deny-network + deny-write profile (`requireCombinedIsolation`); macOS
 *    does not support nesting two sandboxes, so this is a single profile with
 *    its own probe, not a composition.
 *  - both, win32/other → the fs resolver is consulted first and throws, so the
 *    refusal is deterministically `FS_ISOLATION_UNAVAILABLE` rather than
 *    whichever dimension happened to be checked first. Both dimensions are
 *    unavailable on those platforms by design; naming one of them makes the
 *    audit trail reproducible across hosts.
 *
 * Fail closed throughout: any resolver refusal propagates untouched, before a
 * process exists.
 */

export interface IsolationWrap {
  /** The outermost pinned wrapper binary (absolute path). */
  command: string;
  /** Vault-authored prefix args, any inner wrapper, then the payload argv. */
  args: string[];
  /** Set when the wrap delivers network isolation. */
  networkMechanism?: NetworkIsolationMechanism;
  /** Set when the wrap delivers filesystem isolation. */
  fsMechanism?: FsIsolationMechanism;
}

/** The isolation dimensions a secret's policy demands for this spawn. */
export interface IsolationDimensions {
  network: boolean;
  fs: boolean;
}

/**
 * Wrap an already-resolved command in the platform's isolation wrappers for
 * the demanded dimensions, or throw the refusal of whichever dimension cannot
 * be delivered (`NETWORK_ISOLATION_UNAVAILABLE` / `FS_ISOLATION_UNAVAILABLE`).
 *
 * Callers must demand at least one dimension — an all-false call is a caller
 * bug (the seam checks the flags before it composes), not a policy refusal, so
 * it throws a plain Error that no error-code mapping will dress up as a
 * platform limitation.
 */
export async function requireIsolation(
  command: string,
  args: readonly string[],
  dims: IsolationDimensions,
): Promise<IsolationWrap> {
  if (!dims.network && !dims.fs) {
    throw new Error("requireIsolation called with no dimension demanded");
  }

  if (dims.network && dims.fs) {
    if (process.platform === "darwin") {
      const combined = await requireCombinedIsolation(command, args);
      return {
        command: combined.command,
        args: combined.args,
        networkMechanism: "sandbox-exec",
        fsMechanism: combined.mechanism,
      };
    }
    const fsWrap = await requireFsIsolation(command, args);
    const netWrap = await requireNetworkIsolation(fsWrap.command, fsWrap.args);
    if (fsWrap.mechanism === "landlock" && netWrap.mechanism === "unshare") {
      return {
        command: netWrap.command,
        args: netWrap.args,
        networkMechanism: netWrap.mechanism,
        fsMechanism: fsWrap.mechanism,
      };
    }
    const combined = await requireCombinedIsolation(command, args);
    return {
      command: combined.command,
      args: combined.args,
      networkMechanism: "bwrap",
      fsMechanism: combined.mechanism,
    };
  }

  if (dims.fs) {
    const fsWrap = await requireFsIsolation(command, args);
    return { command: fsWrap.command, args: fsWrap.args, fsMechanism: fsWrap.mechanism };
  }

  const netWrap = await requireNetworkIsolation(command, [...args]);
  return { command: netWrap.command, args: netWrap.args, networkMechanism: netWrap.mechanism };
}
