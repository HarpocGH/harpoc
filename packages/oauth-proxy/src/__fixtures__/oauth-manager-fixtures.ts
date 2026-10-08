import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { afterAll, beforeAll, vi } from "vitest";
import type { Mock, MockInstance } from "vitest";
import type { OAuthProviderConfig } from "@harpoc/shared";
import type { VaultEngine } from "@harpoc/core";
import { CallbackServer } from "../callback-server.js";
import { OAuthManager } from "../oauth-manager.js";
import type { OAuthManagerOptions } from "../oauth-manager.js";

export type Handler = (req: IncomingMessage, res: ServerResponse) => void;

export const defaultTokenHandler: Handler = (_req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      access_token: "mgr-access-token",
      refresh_token: "mgr-refresh-token",
      expires_in: 3600,
    }),
  );
};

/** Two loopback servers for the file; each request goes to the handler the getter returns now. */
export function useLoopbackEndpoints(
  tokenHandler: () => Handler,
  deviceHandler: () => Handler,
): { tokenUrl: () => string; deviceUrl: () => string } {
  let tokenServer: Server;
  let tokenServerUrl = "";
  let deviceServer: Server;
  let deviceServerUrl = "";

  beforeAll(async () => {
    tokenServer = createServer((req, res) => {
      tokenHandler()(req, res);
    });
    await new Promise<void>((resolve) => {
      tokenServer.listen(0, "127.0.0.1", () => resolve());
    });
    const tokenAddr = tokenServer.address() as { port: number };
    tokenServerUrl = `http://127.0.0.1:${tokenAddr.port}`;

    deviceServer = createServer((req, res) => {
      deviceHandler()(req, res);
    });
    await new Promise<void>((resolve) => {
      deviceServer.listen(0, "127.0.0.1", () => resolve());
    });
    const deviceAddr = deviceServer.address() as { port: number };
    deviceServerUrl = `http://127.0.0.1:${deviceAddr.port}`;
  });

  afterAll(() => {
    tokenServer.close();
    deviceServer.close();
  });

  return { tokenUrl: () => tokenServerUrl, deviceUrl: () => deviceServerUrl };
}

export function clientCredentialsConfig(tokenUrl: string): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "client_credentials",
    token_endpoint: tokenUrl,
    client_id: "cc-client",
    client_secret: "cc-secret",
    scopes: ["api.read"],
  };
}

export function authCodeConfig(tokenUrl: string): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "authorization_code",
    token_endpoint: tokenUrl,
    auth_endpoint: "https://example.com/auth",
    client_id: "auth-code-client",
    client_secret: "auth-code-secret",
  };
}

export function deviceCodeConfig(tokenUrl: string, deviceUrl: string): OAuthProviderConfig {
  return {
    provider: "custom",
    grant_type: "device_code",
    token_endpoint: tokenUrl,
    device_authorization_endpoint: deviceUrl,
    client_id: "device-client",
  };
}

export interface FakeEngine {
  createOAuthSecret: Mock;
  completeOAuthFlow: Mock;
}

export function makeFakeEngine(): FakeEngine {
  return {
    createOAuthSecret: vi.fn(async () => ({ handle: "secret://gh", secretId: "sid-1" })),
    completeOAuthFlow: vi.fn(async () => undefined),
  };
}

export function fakeEngineManager(fake: FakeEngine, options?: OAuthManagerOptions): OAuthManager {
  return new OAuthManager(fake as unknown as VaultEngine, options);
}

/** Distinct secretId per name — the cap is about *concurrent* flows. */
export function makePerNameFakeEngine(): FakeEngine {
  return {
    createOAuthSecret: vi.fn(async (name: string) => ({
      handle: `secret://${name}`,
      secretId: `sid-${name}`,
    })),
    completeOAuthFlow: vi.fn(async () => undefined),
  };
}

/**
 * Hold every `CallbackServer.start` inside the bind: the spy waits for
 * `releaseBind()` and then delegates to the real implementation, so a test can
 * observe a flow that has been started but has not yet bound its port.
 */
export function gateCallbackServerStart(): {
  startSpy: MockInstance<CallbackServer["start"]>;
  releaseBind: () => void;
} {
  let releaseBind: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    releaseBind = resolve;
  });
  const realStart = CallbackServer.prototype.start;
  const startSpy = vi.spyOn(CallbackServer.prototype, "start").mockImplementation(async function (
    this: CallbackServer,
    state: string,
    timeoutMs?: number,
  ) {
    await gate;
    return realStart.call(this, state, timeoutMs);
  });
  return { startSpy, releaseBind };
}
