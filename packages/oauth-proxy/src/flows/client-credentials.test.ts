import { createServer } from "node:http";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { ClientCredentialsFlow } from "./client-credentials.js";

let tokenServer: Server;
let tokenServerUrl: string;
let tokenHandler: (
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
) => void;

beforeAll(async () => {
  tokenServer = createServer((req, res) => {
    tokenHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    tokenServer.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = tokenServer.address() as { port: number };
  tokenServerUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  tokenServer.close();
});

function makeConfig(overrides?: Partial<OAuthProviderConfig>): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "client_credentials",
    token_endpoint: tokenServerUrl,
    client_id: "service-client",
    client_secret: "service-secret",
    scopes: ["read", "write"],
    ...overrides,
  };
}

describe("ClientCredentialsFlow", () => {
  const flow = new ClientCredentialsFlow();

  it("exchanges client credentials for access token", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "cc-access-token", expires_in: 3600 }));
    };

    const result = await flow.authenticate(makeConfig());
    expect(result.access_token).toBe("cc-access-token");
    expect(result.expires_in).toBe(3600);
  });

  it("handles response without expires_in", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "tok" }));
    };

    const result = await flow.authenticate(makeConfig());
    expect(result.access_token).toBe("tok");
    expect(result.expires_in).toBeUndefined();
  });

  it("throws when client_secret is missing", async () => {
    await expect(
      flow.authenticate(makeConfig({ client_secret: undefined })),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
  });

  it("throws OAUTH_TOKEN_EXCHANGE_FAILED on HTTP error", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_client" }));
    };

    await expect(flow.authenticate(makeConfig())).rejects.toMatchObject({
      code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED,
    });
  });

  it("throws when no access_token in response", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ token_type: "bearer" }));
    };

    await expect(flow.authenticate(makeConfig())).rejects.toMatchObject({
      code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED,
    });
  });

  it("throws on invalid JSON response", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("not json");
    };

    await expect(flow.authenticate(makeConfig())).rejects.toMatchObject({
      code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED,
    });
  });
});
