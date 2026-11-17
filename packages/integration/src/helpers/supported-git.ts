import { execFileSync } from "node:child_process";
import {
  controlledPathDirs,
  GIT_MIN_VERSION,
  gitVersionAtLeast,
  parseGitVersion,
  resolveExecutable,
} from "@harpoc/core";

export function resolveSupportedGit(
  floor: readonly [number, number] = GIT_MIN_VERSION,
): string | null {
  const git = resolveExecutable("git", controlledPathDirs());
  if (git === null) return null;
  const version = parseGitVersion(
    execFileSync(git, ["version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 20_000,
    }),
  );
  return version !== null && gitVersionAtLeast(version, floor) ? git : null;
}
