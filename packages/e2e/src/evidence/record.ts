import { appendFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname } from "node:path";

export interface EvidenceRecord {
  scenario: string;
  context: string;
  surface: string;
  /**
   * The ACCESS INTERFACE this cell counts toward — the second dimension of the
   * Ch. 1 §1.4 matrix. Recorded rather than derived: MCP is one interface with
   * two transports, so `surface` alone cannot be mapped back to an interface
   * without re-implementing that rule in every consumer. `engine` marks a
   * record that is not an access-interface cell (the machinery self-check).
   */
  interface: string;
  arm: "baseline" | "harpoc";
  expected: string;
  observed: string;
  match: boolean;
  commit: string;
  at: string;
  host_os: string;
  /**
   * Whether the working tree carried uncommitted changes when this record was
   * emitted. Without it the C-5 pin is defeatable in silence: a run against a
   * dirty tree stamps a SHA that does not contain the code that produced the
   * evidence, and reads exactly like a clean run.
   */
  dirty: boolean;
}

let cached: string | null = null;
let cachedDirty: boolean | null = null;

/** The artifact pin (C-5). Results that carry their own SHA cannot drift. */
export function commitSha(): string {
  if (cached === null) {
    try {
      cached = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    } catch {
      cached = "unknown";
    }
  }
  return cached;
}

/**
 * Whether the tree the run measured differs from the commit it stamps. A failed
 * git invocation reports `true`: the honest answer to "can this SHA be trusted
 * to describe the code?" when the question cannot be answered is no.
 */
export function treeDirty(): boolean {
  if (cachedDirty === null) {
    try {
      cachedDirty =
        execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim() !== "";
    } catch {
      cachedDirty = true;
    }
  }
  return cachedDirty;
}

/**
 * R-1: the vault side runs on the native OS while the backends stay Linux
 * containers, so a committed Windows/macOS run and the CI Linux run must be
 * distinguishable in the evidence. Expectations stay OS-agnostic (outcomes
 * match across OSes); this stamp is forensic, keyed off nothing.
 */
export function hostOs(): string {
  return process.platform;
}

export function emit(
  filePath: string,
  input: Omit<EvidenceRecord, "match" | "commit" | "at" | "host_os" | "dirty">,
): EvidenceRecord {
  const record: EvidenceRecord = {
    ...input,
    match: input.expected === input.observed,
    commit: commitSha(),
    at: new Date().toISOString(),
    host_os: hostOs(),
    dirty: treeDirty(),
  };
  mkdirSync(dirname(filePath), { recursive: true });
  appendFileSync(filePath, `${JSON.stringify(record)}\n`, "utf8");
  return record;
}
