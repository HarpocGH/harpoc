import { execFileSync } from "node:child_process";
import {
  controlledPathDirs,
  GIT_MIN_VERSION,
  GIT_WIN32_OWNER_MIN_VERSION,
  gitVersionAtLeast,
  parseGitVersion,
  resolveExecutable,
} from "@harpoc/core";
import type { GitVersionFloor } from "@harpoc/core";

export function resolveSupportedGit(
  floor: GitVersionFloor = process.platform === "win32"
    ? GIT_WIN32_OWNER_MIN_VERSION
    : GIT_MIN_VERSION,
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
