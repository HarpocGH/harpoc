import { execFile } from "node:child_process";

export interface GitVersion {
  major: number;
  minor: number;
  patch: number;
}

export const GIT_MIN_VERSION = [2, 32] as const;

export const GIT_PIN_MIN_VERSION = [2, 37] as const;

const GIT_VERSION_TIMEOUT_MS = 10_000;

/** The numbers of a `git version` line, a missing patch read as 0; `null` for any other text. */
export function parseGitVersion(stdout: string): GitVersion | null {
  const match = /^git version (\d+)\.(\d+)(?:\.(\d+))?/.exec(stdout);
  if (match === null) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3] ?? "0") };
}

/** Whether `version` is at or above `floor`, judged on major and minor. */
export function gitVersionAtLeast(version: GitVersion, floor: readonly [number, number]): boolean {
  const [major, minor] = floor;
  return version.major > major || (version.major === major && version.minor >= minor);
}

export function formatGitVersion(version: GitVersion): string {
  return `${String(version.major)}.${String(version.minor)}.${String(version.patch)}`;
}

/**
 * The version of the git at `gitPath`, read from `git version` under `env`, without a shell,
 * within `timeoutMs` and 4 KiB of output; `null` on any failure, a non-zero exit included.
 */
export function readGitVersion(
  gitPath: string,
  env: Record<string, string>,
  timeoutMs = GIT_VERSION_TIMEOUT_MS,
): Promise<GitVersion | null> {
  return new Promise((resolve) => {
    try {
      execFile(
        gitPath,
        ["version"],
        {
          env,
          shell: false,
          timeout: timeoutMs,
          windowsHide: true,
          maxBuffer: 4096,
          encoding: "utf8",
        },
        (err, stdout) => resolve(err === null ? parseGitVersion(stdout) : null),
      );
    } catch {
      resolve(null);
    }
  });
}
