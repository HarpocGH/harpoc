import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { VaultError } from "@harpoc/shared";
import type { SshPublicKey } from "./ssh-common-keys.js";

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
  try {
    writeFileSync(file, content, { mode: 0o600 });
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
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

export interface KnownHostsFiles extends TempSshFile {
  /** An empty file beside `file`, ssh's GlobalKnownHostsFile: never `none`, which a client before 8.5 reads as a file in its working directory. */
  globalFile: string;
}

/**
 * Write pinned host keys to a 0600 known_hosts file in a 0700 temp directory,
 * and beside it an empty 0600 global_known_hosts; one disposer removes both.
 * Host keys are public, so disk is acceptable (unlike the private key, which the
 * ephemeral agent keeps in memory). Shared by the SSH and Git-over-SSH contexts.
 */
export function writeKnownHosts(knownHosts: string[]): KnownHostsFiles {
  const pinned = writeTempSshFile("harpoc-ssh-", "known_hosts", knownHosts.join("\n") + "\n");
  const globalFile = join(dirname(pinned.file), "global_known_hosts");
  try {
    writeFileSync(globalFile, "", { mode: 0o600, flag: "wx" });
  } catch (err) {
    pinned.dispose();
    throw err;
  }
  return { ...pinned, globalFile };
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

/** No configuration file, and strict host-key checking against the vault's pin and its empty global file alone. */
function sshHostKeyArgs(knownHosts: Pick<KnownHostsFiles, "file" | "globalFile">): string[] {
  return [
    "-F",
    "none",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${quoteSshOptionValue(knownHosts.file)}`,
    "-o",
    `GlobalKnownHostsFile=${quoteSshOptionValue(knownHosts.globalFile)}`,
  ];
}

/**
 * Hardened ssh options (thesis §4.5.7): strict host-key verification against the
 * pinned known_hosts alone (no TOFU, and no host-wide `ssh_known_hosts` — S9:
 * the global file is the empty one `writeKnownHosts` writes beside the pin),
 * agent-only auth, and no user ssh config. Shared
 * verbatim by the SSH context (as argv) and the Git-over-SSH context (folded
 * into GIT_SSH_COMMAND).
 *
 * `identityFile` is the vault-written .pub of the ephemeral key and is required:
 * IdentitiesOnly=yes restricts ssh to configured identity files, so the explicit
 * `-i` is what (a) makes the agent-held key eligible at all and (b) drops the
 * default ~/.ssh/id_* candidates — ssh attempts exactly the vault identity.
 */
export function sshHardeningArgs(
  knownHosts: Pick<KnownHostsFiles, "file" | "globalFile">,
  identityFile: string,
  connectTimeoutSec = 15,
): string[] {
  return [
    ...sshHostKeyArgs(knownHosts),
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

/**
 * The ssh bootstrap's options: `sshHardeningArgs`'s host-key pairs, then password login as
 * the one method through the forced askpass helper, no agent, no identity, no sharing, no
 * forwarding, no terminal and no escape character. Both spellings of the keyboard-interactive
 * switch: on 8.4 to 8.6 `KbdInteractiveAuthentication=no` alone does not turn the method off.
 * `LogLevel=ERROR` drops the server's banner and keeps ssh's refusal line.
 */
export function sshPasswordLoginArgs(
  knownHosts: Pick<KnownHostsFiles, "file" | "globalFile">,
  connectTimeoutSec: number,
): string[] {
  return [
    ...sshHostKeyArgs(knownHosts),
    "-o",
    "PreferredAuthentications=password",
    "-o",
    "PubkeyAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-o",
    "ChallengeResponseAuthentication=no",
    "-o",
    "PasswordAuthentication=yes",
    "-o",
    "NumberOfPasswordPrompts=1",
    "-o",
    "BatchMode=no",
    "-o",
    `ConnectTimeout=${connectTimeoutSec}`,
    "-o",
    "IdentityAgent=none",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "IdentityFile=none",
    "-o",
    "CheckHostIP=no",
    "-o",
    "UpdateHostKeys=no",
    "-o",
    "VerifyHostKeyDNS=no",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "RequestTTY=no",
    "-o",
    "EscapeChar=none",
    "-o",
    "LogLevel=ERROR",
  ];
}

/** One known_hosts line per key: the bare host for port 22, `[host]:port` otherwise. */
export function knownHostsLines(
  host: string,
  port: number,
  keys: readonly SshPublicKey[],
): string[] {
  const name = port === 22 ? host : `[${host}]:${String(port)}`;
  return keys.map((key) => `${name} ${key.line}`);
}

/** The password prompt OpenSSH builds for `user` on `host`, one blank after the colon. */
export function sshPasswordPrompt(user: string, host: string): string {
  return `${user}@${host}'s password: `;
}

/** The charset of `sshHostSchema` and `sshUserSchema`: 1–255 of letters, digits, `.`, `_`, `-`, not leading with `.`, `_` or `-`. */
export const SSH_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;

/** True when `text` is a string whose first character is `-`. */
export function startsWithDash(text: unknown): boolean {
  return typeof text === "string" && text.startsWith("-");
}

/** True when `text` is a name of the ssh and sftp contexts' charset (`SSH_NAME`). */
export function isSshName(text: unknown): boolean {
  return typeof text === "string" && SSH_NAME.test(text);
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
  const env = baseSshEnv(envAllowlist);
  env.SSH_AUTH_SOCK = authSock;
  return env;
}

/** `buildSshEnv` without the agent socket: PATH, on Windows SystemRoot and ProgramData, and the allowlisted names. */
export function baseSshEnv(envAllowlist: readonly string[]): Record<string, string> {
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
  return env;
}

/**
 * The ssh bootstrap's environment: `baseSshEnv` without the agent socket's and the display's
 * variables, then the forced askpass helper and its three variables, written after the
 * allowlisted names so an entry cannot shadow them.
 */
export function buildSshPasswordEnv(
  envAllowlist: readonly string[],
  helper: { launcher: string; prompt: string; word: string; password: string },
): Record<string, string> {
  const env = baseSshEnv(envAllowlist);
  delete env.SSH_AUTH_SOCK;
  delete env.DISPLAY;
  delete env.WAYLAND_DISPLAY;
  env.SSH_ASKPASS = helper.launcher;
  env.SSH_ASKPASS_REQUIRE = "force";
  env.HARPOC_SSH_PROMPT = helper.prompt;
  env.HARPOC_SSH_WORD = helper.word;
  env.HARPOC_SSH_PASSWORD = helper.password;
  return env;
}

const NON_NATIVE_RUNTIME_DLLS = ["msys-2.0.dll", "cygwin1.dll"];

/**
 * Refuse an MSYS or Cygwin ssh/sftp build on Windows before it is spawned
 * (R11/D58). Only the native Win32-OpenSSH client can open the agent's named
 * pipe; an MSYS build (the Git-bundled `ssh.exe`) finds no agent, offers the
 * one identity it cannot sign for and dies as exit 255 "Permission denied
 * (publickey)" — a misleading SSH_CONNECT_FAILED. The runtime DLL sits beside
 * the binary in every such distribution, so one stat per name decides. The
 * message names the directory, never the binary path or any argument. A
 * no-op off win32.
 */
export function assertNativeWin32SshClient(resolvedPath: string): void {
  if (process.platform !== "win32") return;
  const directory = dirname(resolvedPath);
  for (const dll of NON_NATIVE_RUNTIME_DLLS) {
    let isFile = false;
    try {
      isFile = statSync(join(directory, dll)).isFile();
    } catch {
      // not here — the next name
    }
    if (isFile) throw VaultError.sshClientUnsupported(directory);
  }
}
