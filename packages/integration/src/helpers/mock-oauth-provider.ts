import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface MockOAuthTokens {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

export interface MockOAuthProvider {
  /** `POST`-able token endpoint on loopback (schema-legal plain HTTP). */
  tokenEndpoint: string;
  /** Every form-encoded token request body, in arrival order. */
  requests: Array<Record<string, string>>;
  setNextTokens(tokens: MockOAuthTokens): void;
  close(): Promise<void>;
}

const DEFAULT_TOKENS: MockOAuthTokens = { access_token: "mock-access-token", expires_in: 3600 };

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/**
 * Minimal OAuth token endpoint on `127.0.0.1:0` for the lifecycle tests: it
 * answers `POST /token` with the configured token JSON and records each
 * form-encoded request body, so a test can assert what actually reached the
 * provider (the client secret, the refresh token) versus what came back over
 * the vault's own wire.
 */
export async function startMockOAuthProvider(): Promise<MockOAuthProvider> {
  const requests: Array<Record<string, string>> = [];
  let tokens: MockOAuthTokens = { ...DEFAULT_TOKENS };

  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    void (async () => {
      const path = (req.url ?? "/").split("?")[0];
      if (req.method !== "POST" || path !== "/token") {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not_found" }));
        return;
      }
      requests.push(Object.fromEntries(new URLSearchParams(await readBody(req))));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: tokens.access_token,
          token_type: "Bearer",
          ...(tokens.refresh_token ? { refresh_token: tokens.refresh_token } : {}),
          ...(tokens.expires_in ? { expires_in: tokens.expires_in } : {}),
        }),
      );
    })();
  };

  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    tokenEndpoint: `http://127.0.0.1:${port}/token`,
    requests,
    setNextTokens(next: MockOAuthTokens): void {
      tokens = { ...next };
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        // The vault's fetch keeps its connection alive, so `close` alone would
        // wait out the keep-alive timeout before its callback fires.
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
