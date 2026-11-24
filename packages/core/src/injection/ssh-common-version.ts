import { execFile } from "node:child_process";
import { VaultError } from "@harpoc/shared";
import { baseSshEnv } from "./ssh-common.js";

export interface SshVersion {
  major: number;
  minor: number;
}

export const SSH_PASSWORD_LOGIN_MIN_VERSION = [8, 4] as const;

const SSH_VERSION_TIMEOUT_MS = 10_000;

/** The numbers of an OpenSSH or Win32-OpenSSH `ssh -V` line; `null` for any other text. */
export function parseSshVersion(stderr: string): SshVersion | null {
  const match = /^OpenSSH_(?:for_Windows_)?(\d+)\.(\d+)/.exec(stderr);
  if (match === null) return null;
  return { major: Number(match[1]), minor: Number(match[2]) };
}

/** Whether `version` is at or above `floor`, judged on major, then minor. */
export function sshVersionAtLeast(version: SshVersion, floor: readonly [number, number]): boolean {
  const [major, minor] = floor;
  if (version.major !== major) return version.major > major;
  return version.minor >= minor;
}

export function formatSshVersion(version: SshVersion): string {
  return `${String(version.major)}.${String(version.minor)}`;
}

/**
 * The version of the ssh client at `sshPath`, read from the standard error of `ssh -V` under
 * `env`, without a shell, within `timeoutMs` and 4 KiB of output; `null` on any failure, a
 * non-zero exit included.
 */
export function readSshVersion(
  sshPath: string,
  env: Record<string, string>,
  timeoutMs = SSH_VERSION_TIMEOUT_MS,
): Promise<SshVersion | null> {
  return new Promise((resolve) => {
    try {
      execFile(
        sshPath,
        ["-V"],
        {
          env,
          shell: false,
          timeout: timeoutMs,
          windowsHide: true,
          maxBuffer: 4096,
          encoding: "utf8",
        },
        (err, _stdout, stderr) => resolve(err === null ? parseSshVersion(stderr) : null),
      );
    } catch {
      resolve(null);
    }
  });
}

/**
 * Refuse, `SSH_CLIENT_UNSUPPORTED`, an ssh client below `SSH_PASSWORD_LOGIN_MIN_VERSION` or
 * whose version cannot be read: a client that is no OpenSSH has no `SSH_ASKPASS_REQUIRE`.
 */
export async function refuseUnsupportedSshClient(
  sshPath: string,
  envAllowlist: readonly string[],
): Promise<void> {
  const version = await readSshVersion(sshPath, baseSshEnv(envAllowlist));
  const floor = SSH_PASSWORD_LOGIN_MIN_VERSION.join(".");
  if (version === null) throw VaultError.sshClientBelowFloor(null, floor);
  if (!sshVersionAtLeast(version, SSH_PASSWORD_LOGIN_MIN_VERSION)) {
    throw VaultError.sshClientBelowFloor(formatSshVersion(version), floor);
  }
}
