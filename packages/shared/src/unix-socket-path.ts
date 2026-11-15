import { MAX_UNIX_SOCKET_PATH_BYTES, MAX_UNIX_SOCKET_PATH_BYTES_DARWIN } from "./constants.js";

/**
 * The bytes a Unix socket path may hold on `platform` (a Node platform name):
 * macOS's own bound on macOS (`"darwin"`: `sun_path`'s 104 bytes less the
 * NUL, 103), Linux's on every other platform (108 less the NUL, 107). The one
 * bound of the CLI's consumer listing, the ladder ahead of the egress proxy's
 * and the agent socket's binds, and the ephemeral ssh-agent's socket, so a
 * path over it is refused naming its length before any bind.
 */
export function maxUnixSocketPathBytes(platform: string): number {
  return platform === "darwin" ? MAX_UNIX_SOCKET_PATH_BYTES_DARWIN : MAX_UNIX_SOCKET_PATH_BYTES;
}
