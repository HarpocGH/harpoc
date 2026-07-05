import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import { VaultError } from "@harpoc/shared";

const { AgentProtocol, utils } = ssh2;

/**
 * An ephemeral, in-process ssh-agent (thesis §4.5.7). The private key is parsed
 * into memory and served over the OpenSSH agent protocol on a per-session socket
 * — a unix-domain socket in a 0700 temp directory on POSIX, a named pipe on
 * Windows (which Win32-OpenSSH's ssh.exe accepts via SSH_AUTH_SOCK). The agent
 * releases signatures only, never key material; the key never touches disk. The
 * socket and directory are removed on `dispose()`, confining the socket-hijack
 * window to the single command.
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
    const parsed = utils.parseKey(privateKeyPem);
    if (parsed instanceof Error) {
      return Promise.reject(VaultError.sshAgentFailed(`invalid private key: ${parsed.message}`));
    }
    const key: ParsedKey = Array.isArray(parsed) ? parsed[0] : parsed;

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

        const agent = new AgentProtocol(false);
        agent.on("identities", (req) => {
          try {
            agent.getIdentitiesReply(req, [key]);
          } catch {
            agent.failureReply(req);
          }
        });
        agent.on("sign", (req, _pubKey, data, options) => {
          try {
            agent.signReply(req, key.sign(data, options.hash));
          } catch {
            agent.failureReply(req);
          }
        });
        agent.on("error", () => {
          /* malformed agent request — ignore */
        });

        stream.pipe(agent).pipe(stream);
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
