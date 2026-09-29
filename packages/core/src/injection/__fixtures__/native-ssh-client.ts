import { ErrorCode, VaultError } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "../allowlist.js";
import { assertNativeWin32SshClient } from "../ssh-common.js";

/** The ssh-family client the product would accept on this host, or null — an MSYS/Cygwin build reads as absent so its suites skip rather than red. */
export function resolveNativeSshClient(command: "ssh" | "sftp"): string | null {
  const resolved = resolveExecutable(command, controlledPathDirs());
  if (resolved === null) return null;
  try {
    assertNativeWin32SshClient(resolved);
  } catch (err) {
    if (err instanceof VaultError && err.code === ErrorCode.SSH_CLIENT_UNSUPPORTED) return null;
    throw err;
  }
  return resolved;
}
