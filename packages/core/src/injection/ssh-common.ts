import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A file written for one ssh invocation, removed with its directory on dispose. */
export interface TempSshFile {
  file: string;
  dispose: () => void;
}

/**
 * Write `content` to a 0600 file named `name` inside a fresh 0700 temp
 * directory prefixed `prefix`, returning the file path and a best-effort
 * disposer that removes the whole directory. This is the one place the
 * mkdtempSync → writeFileSync(mode 0600) → rmSync(recursive, force)
 * shape is defined — shared by every SSH-family per-invocation temp file:
 * the pinned known_hosts, the ephemeral agent's public identity, and (core's
 * sftp-injector) the vault-authored batch file — and, since Wave 2, the git
 * injector's HTTPS CA pin (D64), the one consumer outside the SSH family.
 */
export function writeTempSshFile(prefix: string, name: string, content: string): TempSshFile {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const file = join(dir, name);
  writeFileSync(file, content, { mode: 0o600 });
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
 * Write pinned host keys to a 0600 known_hosts file in a 0700 temp directory.
 * Host keys are public, so disk is acceptable (unlike the private key, which the
 * ephemeral agent keeps in memory). Shared by the SSH and Git-over-SSH contexts.
 */
export function writeKnownHosts(knownHosts: string[]): TempSshFile {
  return writeTempSshFile("harpoc-ssh-", "known_hosts", knownHosts.join("\n") + "\n");
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
  return writeTempSshFile("harpoc-ssh-id-", "identity.pub", publicKeyLine + "\n");
}

/**
 * Double-quote an ssh option VALUE for readconf. ssh re-tokenizes option values
 * on whitespace after argv is already split — a space in an unquoted
 * UserKnownHostsFile path yields two filenames, so a pinned known_hosts under
 * "C:/Users/Stefan G/…" silently stops matching and strict checking refuses a
 * correctly pinned host. Double quotes are readconf's documented grouping
 * mechanism; backslashes stay literal inside them and `$` is never expanded
 * (verified live on Win32-OpenSSH 9.5p2 and OpenSSH 10.0p2). A value containing
 * a double quote itself is unrepresentable at this layer (readconf has no
 * escape), but `"` cannot appear in an NTFS path and the value is always a
 * vault-authored temp path.
 */
function quoteSshOptionValue(value: string): string {
  return `"${value}"`;
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
    `UserKnownHostsFile=${quoteSshOptionValue(knownHostsFile)}`,
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
