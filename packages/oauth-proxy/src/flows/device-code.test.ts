import { createServer } from "node:http";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { OAuthProviderConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { DeviceCodeFlow } from "./device-code.js";

let deviceServer: Server;
let deviceServerUrl: string;
let tokenServer: Server;
let tokenServerUrl: string;
let deviceHandler: (
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
) => void;
let tokenHandler: (
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
) => void;

beforeAll(async () => {
  deviceServer = createServer((req, res) => {
    deviceHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    deviceServer.listen(0, "127.0.0.1", () => resolve());
  });
  const deviceAddr = deviceServer.address() as { port: number };
  deviceServerUrl = `http://127.0.0.1:${deviceAddr.port}`;

  tokenServer = createServer((req, res) => {
    tokenHandler(req, res);
  });
  await new Promise<void>((resolve) => {
    tokenServer.listen(0, "127.0.0.1", () => resolve());
  });
  const tokenAddr = tokenServer.address() as { port: number };
  tokenServerUrl = `http://127.0.0.1:${tokenAddr.port}`;
});

afterAll(() => {
  deviceServer.close();
  tokenServer.close();
});

function makeConfig(overrides?: Partial<OAuthProviderConfig>): OAuthProviderConfig {
  return {
    provider: "github",
    grant_type: "device_code",
    token_endpoint: tokenServerUrl,
    device_authorization_endpoint: deviceServerUrl,
    client_id: "device-client",
    ...overrides,
  };
}

describe("DeviceCodeFlow.startFlow", () => {
  const flow = new DeviceCodeFlow();

  it("requests a device code from the provider", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          device_code: "ABCD-1234",
          user_code: "EFGH-5678",
          verification_uri: "https://github.com/login/device",
          expires_in: 900,
          interval: 5,
        }),
      );
    };

    const result = await flow.startFlow(makeConfig());
    expect(result.device_code).toBe("ABCD-1234");
    expect(result.user_code).toBe("EFGH-5678");
    expect(result.verification_uri).toBe("https://github.com/login/device");
    expect(result.expires_in).toBe(900);
    expect(result.interval).toBe(5);
  });

  it("throws when device_authorization_endpoint is missing", async () => {
    await expect(
      flow.startFlow(makeConfig({ device_authorization_endpoint: undefined })),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
  });

  it("throws on HTTP error from device endpoint", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(500);
      res.end("Server error");
    };

    await expect(flow.startFlow(makeConfig())).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });
  });

  it("throws when response is missing required fields", async () => {
    deviceHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ device_code: "DC" }));
    };

    await expect(flow.startFlow(makeConfig())).rejects.toMatchObject({
      code: ErrorCode.OAUTH_FLOW_FAILED,
    });
  });
});

describe("DeviceCodeFlow.pollForToken", () => {
  const flow = new DeviceCodeFlow();

  it("returns tokens when authorization is granted", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: "device-access-token",
          refresh_token: "device-refresh-token",
          expires_in: 3600,
        }),
      );
    };

    const result = await flow.pollForToken("DC123", 0, makeConfig(), 30);
    expect(result.access_token).toBe("device-access-token");
    expect(result.refresh_token).toBe("device-refresh-token");
  });

  it("handles authorization_pending then success", async () => {
    let callCount = 0;
    tokenHandler = (_req, res) => {
      callCount++;
      if (callCount < 3) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "authorization_pending" }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "finally-got-it" }));
      }
    };

    const result = await flow.pollForToken("DC-pending", 0, makeConfig(), 30);
    expect(result.access_token).toBe("finally-got-it");
    expect(callCount).toBe(3);
  });

  it("throws on access_denied", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "access_denied" }));
    };

    await expect(
      flow.pollForToken("DC-denied", 0, makeConfig(), 30),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
  });

  it("throws on expired_token", async () => {
    tokenHandler = (_req, res) => {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "expired_token" }));
    };

    await expect(
      flow.pollForToken("DC-expired", 0, makeConfig(), 30),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_CALLBACK_TIMEOUT });
  });

  it("respects abort signal", async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(
      flow.pollForToken("DC-abort", 0, makeConfig(), 30, controller.signal),
    ).rejects.toMatchObject({ code: ErrorCode.OAUTH_FLOW_FAILED });
  });
});
