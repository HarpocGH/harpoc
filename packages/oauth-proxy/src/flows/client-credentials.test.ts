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

  it("rejects a private-address token_endpoint before the client_secret is sent", async () => {
    await expect(
      flow.authenticate(makeConfig({ token_endpoint: "https://192.168.1.1/token" })),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
  });

  it("rejects a non-loopback plain-HTTP token_endpoint", async () => {
    await expect(
      flow.authenticate(makeConfig({ token_endpoint: "http://169.254.169.254/token" })),
    ).rejects.toMatchObject({ code: ErrorCode.URL_HTTPS_REQUIRED });
  });
});

describe("ClientCredentialsFlow token endpoint auth methods (code review Low O5)", () => {
  const flow = new ClientCredentialsFlow();

  it("client_secret_basic sends Authorization: Basic and keeps credentials out of the body", async () => {
    let auth: string | undefined;
    let body = "";
    tokenHandler = (req, res) => {
      auth = req.headers.authorization;
      let data = "";
      req.on("data", (c: Buffer) => (data += c.toString()));
      req.on("end", () => {
        body = data;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "tok" }));
      });
    };

    await flow.authenticate(makeConfig({ token_endpoint_auth_method: "client_secret_basic" }));

    const expected = `Basic ${Buffer.from("service-client:service-secret", "utf8").toString("base64")}`;
    expect(auth).toBe(expected);
    expect(body).toContain("grant_type=client_credentials");
    expect(body).not.toContain("client_secret");
    expect(body).not.toContain("service-secret");
  });

  it("client_secret_post (the default) keeps credentials in the body with no auth header", async () => {
    let auth: string | undefined;
    let body = "";
    tokenHandler = (req, res) => {
      auth = req.headers.authorization;
      let data = "";
      req.on("data", (c: Buffer) => (data += c.toString()));
      req.on("end", () => {
        body = data;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "tok" }));
      });
    };

    await flow.authenticate(makeConfig());

    expect(auth).toBeUndefined();
    expect(body).toContain("client_id=service-client");
    expect(body).toContain("client_secret=service-secret");
  });
});
