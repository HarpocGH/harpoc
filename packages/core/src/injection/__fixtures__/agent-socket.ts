import { connect } from "node:net";

/**
 * Whether the ephemeral agent's socket still accepts a connection — `false` once its path
 * is gone (`ENOENT`, the `ssh-agent/index.test.ts` idiom). A connect, not `existsSync`: on
 * win32 the socket is a named pipe, and `existsSync` opens it as a client, reading false
 * while the pipe's free instance is busy — a live pipe would look gone (I8, U2).
 */
export function agentSocketAccepts(sock: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const probe = connect(sock);
    probe.on("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") resolve(false);
      else reject(err);
    });
  });
}
