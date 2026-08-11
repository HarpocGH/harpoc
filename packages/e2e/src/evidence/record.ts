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

export function emit(
  filePath: string,
  input: Omit<EvidenceRecord, "match" | "commit" | "at">,
): EvidenceRecord {
  const record: EvidenceRecord = {
    ...input,
    match: input.expected === input.observed,
    commit: commitSha(),
    at: new Date().toISOString(),
  };
  mkdirSync(dirname(filePath), { recursive: true });
  appendFileSync(filePath, `${JSON.stringify(record)}\n`, "utf8");
  return record;
}
