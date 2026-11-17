import { MAX_UNIX_SOCKET_PATH_BYTES, MAX_UNIX_SOCKET_PATH_BYTES_DARWIN } from "./constants.js";

const SUN_PATH_104_PLATFORMS: ReadonlySet<string> = new Set([
  "darwin",
  "freebsd",
  "openbsd",
  "netbsd",
]);

/**
 * The bytes a Unix socket path may hold on `platform` (a Node platform name):
 * 103 on darwin, FreeBSD, OpenBSD and NetBSD (`sun_path`'s 104 bytes less the
 * NUL), Linux's 107 (108 less the NUL) on every other platform. The one
 * bound of the CLI's consumer listing, the ladder ahead of the egress proxy's
 * and the agent socket's binds, and the ephemeral ssh-agent's socket, so a
 * path over it is refused naming its length before any bind.
 */
export function maxUnixSocketPathBytes(platform: string): number {
  return SUN_PATH_104_PLATFORMS.has(platform)
    ? MAX_UNIX_SOCKET_PATH_BYTES_DARWIN
    : MAX_UNIX_SOCKET_PATH_BYTES;
}
