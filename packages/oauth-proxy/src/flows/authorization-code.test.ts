import { createServer } from "node:http";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { AuthorizationCodeFlow } from "./authorization-code.js";

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
    provider: "github",
    grant_type: "authorization_code",
    token_endpoint: tokenServerUrl,
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "test-client-id",
    client_secret: "test-client-secret",
    scopes: ["repo", "user"],
    ...overrides,
  };
}

describe("AuthorizationCodeFlow.startFlow", () => {
  const flow = new AuthorizationCodeFlow();
  const redirectUri = "http://localhost:19876/oauth/callback";

  it("constructs auth URL with required parameters", () => {
    const config = makeConfig();
    const result = flow.startFlow(config, redirectUri);

    const url = new URL(result.auth_url);
    expect(url.origin + url.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("test-client-id");
    expect(url.searchParams.get("redirect_uri")).toBe(redirectUri);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("includes PKCE code_challenge", () => {
    const result = flow.startFlow(makeConfig(), redirectUri);
    const url = new URL(result.auth_url);

    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("generates unique state per call", () => {
    const r1 = flow.startFlow(makeConfig(), redirectUri);
    const r2 = flow.startFlow(makeConfig(), redirectUri);
    expect(r1.state).not.toBe(r2.state);
  });

  it("state is 64-character hex string (32 random bytes)", () => {
    const result = flow.startFlow(makeConfig(), redirectUri);
    expect(result.state).toHaveLength(64);
    expect(result.state).toMatch(/^[0-9a-f]+$/);
  });

  it("returns code_verifier for token exchange", () => {
    const result = flow.startFlow(makeConfig(), redirectUri);
    expect(result.code_verifier).toHaveLength(43);
    expect(result.code_verifier).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("includes scopes joined by space", () => {
    const result = flow.startFlow(makeConfig(), redirectUri);
    const url = new URL(result.auth_url);
    expect(url.searchParams.get("scope")).toBe("repo user");
  });

  it("omits scope if no scopes configured", () => {
    const result = flow.startFlow(makeConfig({ scopes: undefined }), redirectUri);
    const url = new URL(result.auth_url);
    expect(url.searchParams.get("scope")).toBeNull();
  });

  it("throws when auth_endpoint is missing", () => {
    expect(() =>
      flow.startFlow(makeConfig({ auth_endpoint: undefined }), redirectUri),
    ).toThrow();
  });
});

describe("AuthorizationCodeFlow.handleCallback", () => {
  const flow = new AuthorizationCodeFlow();
  const redirectUri = "http://localhost:19876/oauth/callback";

  it("exchanges code for tokens", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: "gh-access-token",
          refresh_token: "gh-refresh-token",
          expires_in: 7200,
        }),
      );
    };

    const config = makeConfig();
    const result = await flow.handleCallback("auth-code-123", config, redirectUri, "verifier123");

    expect(result.access_token).toBe("gh-access-token");
    expect(result.refresh_token).toBe("gh-refresh-token");
    expect(result.expires_in).toBe(7200);
  });

  it("handles response without refresh_token", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "tok-only" }));
    };

    const result = await flow.handleCallback("code", makeConfig(), redirectUri, "v");
    expect(result.access_token).toBe("tok-only");
    expect(result.refresh_token).toBeUndefined();
    expect(result.expires_in).toBeUndefined();
  });

  it("throws OAUTH_TOKEN_EXCHANGE_FAILED on HTTP error", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    };

    await expect(
      flow.handleCallback("bad-code", makeConfig(), redirectUri, "v"),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED });
  });

  it("throws when response has no access_token", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ token_type: "bearer" }));
    };

    await expect(
      flow.handleCallback("code", makeConfig(), redirectUri, "v"),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_TOKEN_EXCHANGE_FAILED });
  });
});
