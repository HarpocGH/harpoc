import { lstatSync, unlinkSync } from "node:fs";
import { connect } from "node:net";
import { maxUnixSocketPathBytes, VaultError } from "@harpoc/shared";

/** A connect, not `existsSync` (the `agentSocketAccepts` probe): true when something accepts on `path`. */
function socketAccepts(path: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const probe = connect(path);
    probe.on("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED" || err.code === "ENOENT") resolve(false);
      else reject(err);
    });
  });
}

/**
 * The POSIX ladder ahead of a Unix-socket bind, shared by the egress proxy's
 * `listenSocket` and `AgentSocketServer` (lifted from the proxy in B3): a path
 * over `platform`'s `maxUnixSocketPathBytes` (107; darwin 103) is refused
 * naming its length, a path that exists and is not a socket is refused and
 * left, a socket something accepts on is refused, and a stale one — nothing
 * accepts — is unlinked so the bind can take its place. Every refusal is
 * `INVALID_INPUT` prefixed by `label`; the caller refuses Windows and sets the
 * mode after its bind.
 */
export async function prepareUnixSocketPath(
  path: string,
  label: string,
  platform: NodeJS.Platform = process.platform,
): Promise<void> {
  const bytes = Buffer.byteLength(path);
  const max = maxUnixSocketPathBytes(platform);
  if (bytes > max) {
    throw VaultError.invalidInput(
      `${label}: path is ${bytes} bytes, over the ${max} a Unix socket address holds: ${path}`,
    );
  }
  let isSocket: boolean;
  try {
    isSocket = lstatSync(path).isSocket();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (!isSocket) {
    throw VaultError.invalidInput(`${label}: ${path} exists and is not a socket`);
  }
  if (await socketAccepts(path)) {
    throw VaultError.invalidInput(`${label}: another process is listening on ${path}`);
  }
  unlinkSync(path);
}
