import { appendFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname } from "node:path";

export interface EvidenceRecord {
  scenario: string;
  context: string;
  surface: string;
  arm: "baseline" | "harpoc";
  expected: string;
  observed: string;
  match: boolean;
  commit: string;
  at: string;
  host_os: string;
}

let cached: string | null = null;

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
  input: Omit<EvidenceRecord, "match" | "commit" | "at" | "host_os">,
): EvidenceRecord {
  const record: EvidenceRecord = {
    ...input,
    match: input.expected === input.observed,
    commit: commitSha(),
    at: new Date().toISOString(),
    host_os: hostOs(),
  };
  mkdirSync(dirname(filePath), { recursive: true });
  appendFileSync(filePath, `${JSON.stringify(record)}\n`, "utf8");
  return record;
}
