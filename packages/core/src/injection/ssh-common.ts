import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A file written for one ssh invocation, removed with its directory on dispose. */
export interface TempSshFile {
  file: string;
  dispose: () => void;
}

/**
 * Write pinned host keys to a 0600 known_hosts file in a 0700 temp directory.
 * Host keys are public, so disk is acceptable (unlike the private key, which the
 * ephemeral agent keeps in memory). Shared by the SSH and Git-over-SSH contexts.
 */
export function writeKnownHosts(knownHosts: string[]): TempSshFile {
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
 * Write the ephemeral identity's public line to a 0600 file in a 0700 temp
 * directory, for use as ssh's IdentityFile. Only the public half touches disk
 * (harmless, like the pinned host keys); the private key stays confined to the
 * in-process agent. This file is load-bearing: under IdentitiesOnly=yes ssh
 * offers only file-backed identities — without it the agent-only key is never
 * attempted and authentication fails against a host with no ~/.ssh/id_* files
 * (or worse, proceeds with the host user's ambient default keys).
 */
export function writeIdentityFile(publicKeyLine: string): TempSshFile {
  const dir = mkdtempSync(join(tmpdir(), "harpoc-ssh-id-"));
  const file = join(dir, "identity.pub");
  writeFileSync(file, publicKeyLine + "\n", { mode: 0o600 });
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
 *
 * `identityFile` is the vault-written .pub of the ephemeral key and is required:
 * IdentitiesOnly=yes restricts ssh to configured identity files, so the explicit
 * `-i` is what (a) makes the agent-held key eligible at all and (b) drops the
 * default ~/.ssh/id_* candidates — ssh attempts exactly the vault identity.
 */
export function sshHardeningArgs(
  knownHostsFile: string,
  identityFile: string,
  connectTimeoutSec = 15,
): string[] {
  return [
    "-F",
    "none",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${knownHostsFile}`,
    "-o",
    "IdentitiesOnly=yes",
    "-i",
    identityFile,
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
  return (
    /host key verification failed/i.test(text) || /host identification has changed/i.test(text)
  );
}

/**
 * Clean environment for a spawned ssh/git process: controlled PATH, the ephemeral
 * agent socket, allowlisted pass-through vars, plus SystemRoot and ProgramData on
 * Windows — Win32-OpenSSH's ssh.exe needs SystemRoot for its crypto DLLs and
 * exits 255 without any output if ProgramData is absent (it resolves
 * __PROGRAMDATA__\ssh at startup, even under -F none). The vault's own
 * environment is not inherited.
 */
export function buildSshEnv(authSock: string, envAllowlist: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  const path = process.env.PATH ?? process.env.Path;
  if (path) env.PATH = path;
  if (process.platform === "win32") {
    if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
    if (process.env.ProgramData) env.ProgramData = process.env.ProgramData;
  }
  for (const name of envAllowlist) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  env.SSH_AUTH_SOCK = authSock;
  return env;
}
