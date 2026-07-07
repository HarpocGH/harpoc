import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VaultError } from "@harpoc/shared";
import { createAgentResponder } from "./agent-protocol.js";
import { loadPrivateKey } from "./key-loader.js";

/**
 * An ephemeral, in-process ssh-agent (thesis §4.5.7). The private key is parsed
 * into memory and served over the OpenSSH agent protocol on a per-session socket
 * — a unix-domain socket in a 0700 temp directory on POSIX, a named pipe on
 * Windows (which Win32-OpenSSH's ssh.exe accepts via SSH_AUTH_SOCK). The agent
 * releases signatures only, never key material; the key never touches disk. The
 * socket and directory are removed on `dispose()`, confining the socket-hijack
 * window to the single command.
 *
 * The agent protocol, private-key parsing and signing are the vault's own code
 * over `node:crypto` — no third-party cryptographic dependency runs in the vault
 * process (thesis §5.1.1). See `agent-protocol.ts`, `key-loader.ts`, `ssh-wire.ts`.
 */
export class EphemeralSshAgent {
  private constructor(
    /** Value to place in the spawned process's SSH_AUTH_SOCK. */
    readonly authSock: string,
    private server: Server | null,
    private readonly sockets: Set<Socket>,
    private tempDir: string | null,
  ) {}

  static start(privateKeyPem: string): Promise<EphemeralSshAgent> {
    let key: ReturnType<typeof loadPrivateKey>;
    try {
      key = loadPrivateKey(privateKeyPem);
    } catch (err) {
      const message = err instanceof VaultError ? err.message : "invalid private key";
      return Promise.reject(
        err instanceof VaultError ? err : VaultError.sshAgentFailed(message),
      );
    }

    let authSock: string;
    let tempDir: string | null = null;
    if (process.platform === "win32") {
      authSock = `\\\\.\\pipe\\harpoc-ssh-${randomBytes(12).toString("hex")}`;
    } else {
      tempDir = mkdtempSync(join(tmpdir(), "harpoc-agent-"));
      authSock = join(tempDir, "agent.sock");
    }

    const sockets = new Set<Socket>();
    return new Promise<EphemeralSshAgent>((resolvePromise, reject) => {
      const server = createServer((stream: Socket) => {
        sockets.add(stream);
        stream.on("close", () => sockets.delete(stream));
        stream.on("error", () => {
          /* per-connection transport error — ignore, the command will fail visibly */
        });

        const respond = createAgentResponder(key);
        stream.on("data", (chunk: Buffer) => {
          try {
            const reply = respond(chunk);
            if (reply.length > 0) stream.write(reply);
          } catch {
            stream.destroy();
          }
        });
      });

      server.on("error", (err) => {
        if (tempDir) {
          try {
            rmSync(tempDir, { recursive: true, force: true });
          } catch {
            /* best effort */
          }
        }
        reject(VaultError.sshAgentFailed(err.message));
      });

      server.listen(authSock, () => {
        resolvePromise(new EphemeralSshAgent(authSock, server, sockets, tempDir));
      });
    });
  }

  /** Tear down the agent: destroy connections, close the socket, remove the directory. */
  dispose(): void {
    for (const s of this.sockets) {
      try {
        s.destroy();
      } catch {
        /* best effort */
      }
    }
    this.sockets.clear();
    try {
      this.server?.close();
    } catch {
      /* best effort */
    }
    this.server = null;
    if (this.tempDir) {
      try {
        rmSync(this.tempDir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
      this.tempDir = null;
    }
  }
}
