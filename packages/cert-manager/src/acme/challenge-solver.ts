import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { VaultError } from "@harpoc/shared";

const DEFAULT_PORT = 80;
const CHALLENGE_PATH_PREFIX = "/.well-known/acme-challenge/";
const NOT_FOUND_BODY = "not found";
const TEXT_PLAIN = "text/plain";

export class Http01Solver {
  private server: Server | null = null;

  async start(
    token: string,
    keyAuthorization: string,
    port: number = DEFAULT_PORT,
  ): Promise<number> {
    if (this.server !== null) {
      throw VaultError.certAcmeFailed("http-01 challenge server is already started");
    }
    const expectedPath = `${CHALLENGE_PATH_PREFIX}${token}`;
    const server = createServer((req, res) => {
      respond(req, res, expectedPath, keyAuthorization);
    });
    this.server = server;
    return new Promise<number>((resolve, reject) => {
      /* The cause is deliberately discarded, not logged: its text distinguishes
       * EADDRINUSE from EACCES and names the bind interface, which turns every
       * caller surface into a port-occupancy oracle. Only the caller-supplied
       * port — already known to the caller — appears. */
      const onStartError = (): void => {
        this.server = null;
        reject(
          VaultError.certAcmeFailed(`http-01 challenge server failed to start on port ${port}`),
        );
      };
      server.once("error", onStartError);
      /* The ACME CA, not this host, must reach this server, so it binds all
       * interfaces (0.0.0.0) — the one deliberate non-loopback bind in this
       * codebase. */
      server.listen(port, "0.0.0.0", () => {
        server.removeListener("error", onStartError);
        const address = server.address();
        resolve(typeof address === "object" && address !== null ? address.port : port);
      });
    });
  }

  async stop(): Promise<void> {
    const server = this.server;
    if (server === null) return;
    this.server = null;
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
}

function respond(
  req: IncomingMessage,
  res: ServerResponse,
  expectedPath: string,
  keyAuthorization: string,
): void {
  const path = (req.url ?? "").split("?")[0];
  if (req.method === "GET" && path === expectedPath) {
    res.writeHead(200, { "content-type": TEXT_PLAIN });
    res.end(keyAuthorization);
    return;
  }
  res.writeHead(404, { "content-type": TEXT_PLAIN });
  res.end(NOT_FOUND_BODY);
}

export function dns01TxtValue(keyAuthorization: string): string {
  return createHash("sha256").update(keyAuthorization).digest("base64url");
}
