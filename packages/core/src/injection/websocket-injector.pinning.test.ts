import { afterEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy, InjectionPolicyInput, WebsocketAction } from "@harpoc/shared";
import { ActionType, ErrorCode, injectionPolicyInputSchema } from "@harpoc/shared";

// Partial mock: hostnames under *.pinned.test validate successfully and pin to
// the loopback test server; everything else uses the real validator. Mirrors
// http-injector.pinning.test.ts exactly — the .test TLD never resolves in
// real DNS, so a request to these hosts can only succeed if the pinned lookup
// drives the connection.
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(async (urlStr: string, schemes?: unknown) => {
      const url = new URL(urlStr);
      if (url.hostname.endsWith(".pinned.test")) {
        return { url, resolvedAddresses: ["127.0.0.1"] };
      }
      return actual.validateUrl(urlStr, schemes as never);
    }),
  };
});

import type { FakeWsServer } from "./__fixtures__/fake-ws-server.js";
import { startFakeWsServer } from "./__fixtures__/fake-ws-server.js";
import { executeWebsocketAction } from "./websocket-injector.js";

const SECRET = "pin-secret";

function basePolicy(partial: Partial<InjectionPolicyInput> = {}): InjectionPolicy {
  return injectionPolicyInputSchema.parse(partial);
}

function secretBytes(value = SECRET): Uint8Array {
  return new TextEncoder().encode(value);
}

let server: FakeWsServer | undefined;

afterEach(async () => {
  if (server) {
    await server.close();
    server = undefined;
  }
});

describe("WebSocket DNS-rebinding IP pinning", () => {
  it("connects to the pinned address while preserving the Host header and injecting the credential", async () => {
    server = await startFakeWsServer({});
    const port = server.port;

    const action: WebsocketAction = {
      type: ActionType.WEBSOCKET,
      url: `ws://a.pinned.test:${port}/ok`,
      injection: { type: "bearer" },
    } as unknown as WebsocketAction;

    await executeWebsocketAction(
      action,
      secretBytes(),
      basePolicy({ url_allowlist: [`ws://a.pinned.test:${port}/*`] }),
    );

    expect(server.requests()).toHaveLength(1);
    expect(server.requests()[0]?.headers.host).toBe(`a.pinned.test:${port}`);
    expect(server.requests()[0]?.headers.authorization).toBe(`Bearer ${SECRET}`);
  });
});

describe("WebSocket SSRF pinning — literal IPs (no DNS)", () => {
  it("blocks a private literal IP under wss: before dialing", async () => {
    const action: WebsocketAction = {
      type: ActionType.WEBSOCKET,
      url: "wss://10.0.0.1/x",
      injection: { type: "bearer" },
    } as unknown as WebsocketAction;

    await expect(
      executeWebsocketAction(
        action,
        secretBytes(),
        basePolicy({ url_allowlist: ["wss://10.0.0.1/*"] }),
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
  });

  it("blocks an IPv4-mapped IPv6 private literal under wss: before dialing", async () => {
    const action: WebsocketAction = {
      type: ActionType.WEBSOCKET,
      url: "wss://[::ffff:192.168.1.1]/x",
      injection: { type: "bearer" },
    } as unknown as WebsocketAction;

    await expect(
      executeWebsocketAction(
        action,
        secretBytes(),
        basePolicy({ url_allowlist: ["wss://[::ffff:192.168.1.1]/*"] }),
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
  });
});
