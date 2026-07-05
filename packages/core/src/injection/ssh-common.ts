import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface KnownHostsFile {
  file: string;
  dispose: () => void;
}

/**
 * Write pinned host keys to a 0600 known_hosts file in a 0700 temp directory.
 * Host keys are public, so disk is acceptable (unlike the private key, which the
 * ephemeral agent keeps in memory). Shared by the SSH and Git-over-SSH contexts.
 */
export function writeKnownHosts(knownHosts: string[]): KnownHostsFile {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-ssh-"));
  const file = join(dir, "known_hosts");
  writeFileSync(file, knownHosts.join("\n") + "\n", { mode: 0o600 });
  return {
    file,
    dispose: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    },
  };
}

/**
 * Hardened ssh options (thesis §4.5.7): strict host-key verification against the
 * pinned known_hosts (no TOFU), agent-only auth, and no user ssh config. Shared
 * verbatim by the SSH context (as argv) and the Git-over-SSH context (folded
 * into GIT_SSH_COMMAND).
 */
export function sshHardeningArgs(knownHostsFile: string, connectTimeoutSec = 15): string[] {
  return [
    "-F",
    "none",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${knownHostsFile}`,
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "BatchMode=yes",
    "-o",
    "PasswordAuthentication=no",
    "-o",
    `ConnectTimeout=${connectTimeoutSec}`,
  ];
}

/** Detect an ssh host-key verification failure (pinned-key mismatch or unknown host). */
export function isHostKeyFailure(text: string): boolean {
  return /host key verification failed/i.test(text) || /host identification has changed/i.test(text);
}

/**
 * Clean environment for a spawned ssh/git process: controlled PATH, the ephemeral
 * agent socket, allowlisted pass-through vars, plus SystemRoot on Windows (ssh.exe
 * needs it for its crypto DLLs). The vault's own environment is not inherited.
 */
export function buildSshEnv(authSock: string, envAllowlist: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  const path = process.env.PATH ?? process.env.Path;
  if (path) env.PATH = path;
  if (process.platform === "win32" && process.env.SystemRoot) {
    env.SystemRoot = process.env.SystemRoot;
  }
  for (const name of envAllowlist) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  env.SSH_AUTH_SOCK = authSock;
  return env;
}
