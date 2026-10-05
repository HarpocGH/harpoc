import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";

const DNS = vi.hoisted(() => ({ unresolvedHost: "unresolved.pinned.test" }));

// Partial mock: hostnames under *.pinned.test validate successfully and pin to
// the loopback test server, except unresolved.pinned.test, which fails the way
// the real validator fails on ENOTFOUND; any other hostname throws, so no case
// reaches the real resolver. The .test TLD never resolves in real DNS — a
// request to these hosts can only succeed if the pinned lookup drives the
// connection.
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  const shared = await import("@harpoc/shared");
  return {
    ...actual,
    validateUrl: vi.fn(async (urlStr: string) => {
      const url = new URL(urlStr);
      if (url.hostname === DNS.unresolvedHost) {
        throw new shared.VaultError(
          shared.ErrorCode.DNS_RESOLUTION_FAILED,
          `DNS resolution failed for ${url.hostname}: getaddrinfo ENOTFOUND ${url.hostname}`,
        );
      }
      if (url.hostname.endsWith(".pinned.test")) {
        return { url, resolvedAddresses: ["127.0.0.1"] };
      }
      throw new Error(`unexpected host ${url.hostname}`);
    }),
  };
});

import { HttpInjector, createPinnedLookup } from "./http-injector.js";
import { validateUrl } from "./url-validator.js";

interface SeenRequest {
  host: string | undefined;
  url: string | undefined;
  authorization: string | undefined;
}

describe("HTTP DNS-rebinding IP pinning", () => {
  let server: Server;
  let port: number;
  const requests: SeenRequest[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      requests.push({
        host: req.headers.host,
        url: req.url,
        authorization: req.headers.authorization,
      });
      if (req.url === "/hop") {
        res.statusCode = 302;
        res.setHeader("location", `http://b.pinned.test:${port}/final`);
        res.end();
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end('{"ok":true}');
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  beforeEach(() => {
    requests.length = 0;
  });

  it("connects to the pinned address while preserving the Host header", async () => {
    const injector = new HttpInjector(null);
    const result = await injector.executeWithSecret(
      { method: "GET", url: `http://a.pinned.test:${port}/ok` },
      new TextEncoder().encode("pin-secret"),
      { type: "bearer" },
    );

    expect(result.status).toBe(200);
    expect(requests).toHaveLength(1);
    expect(requests.at(0)).toMatchObject({
      host: `a.pinned.test:${port}`,
      authorization: "Bearer pin-secret",
    });
  });

  it("re-validates and re-pins every redirect hop independently", async () => {
    const injector = new HttpInjector(null);
    const result = await injector.executeWithSecret(
      {
        method: "GET",
        url: `http://a.pinned.test:${port}/hop`,
        urlAllowlist: [`http://a.pinned.test:${port}/*`, `http://b.pinned.test:${port}/*`],
      },
      new TextEncoder().encode("pin-secret"),
      { type: "bearer" },
      "any",
    );

    expect(result.status).toBe(200);
    expect(requests.map((r) => r.host)).toEqual([`a.pinned.test:${port}`, `b.pinned.test:${port}`]);
    expect(requests.at(1)?.url).toBe("/final");
  });
});

describe("HTTP DNS resolution failure", () => {
  beforeEach(() => {
    vi.mocked(validateUrl).mockClear();
  });

  it("returns DNS_RESOLUTION_FAILED as a response for a hostname that does not resolve", async () => {
    const url = `https://${DNS.unresolvedHost}/api`;
    const response = await new HttpInjector(null).executeWithSecret(
      { method: "GET", url },
      new TextEncoder().encode("dns-secret"),
      { type: "bearer" },
    );

    expect(response).toEqual({
      type: "http",
      status: null,
      error: ErrorCode.DNS_RESOLUTION_FAILED,
    });
    expect(validateUrl).toHaveBeenCalledExactlyOnceWith(url);
  });
});

describe("createPinnedLookup", () => {
  const pins = new Map<string, readonly string[]>([
    ["api.example.com", ["93.184.216.34", "2606:2800::1"]],
  ]);

  function callLookup(
    hostname: string,
    options: { all?: boolean; family?: number },
  ): Promise<{ err: NodeJS.ErrnoException | null; address: unknown; family: number | undefined }> {
    return new Promise((resolve) => {
      createPinnedLookup(pins)(hostname, options, (err, address, family) => {
        resolve({ err, address, family });
      });
    });
  }

  it("serves all pinned addresses with families (all form)", async () => {
    const { err, address } = await callLookup("api.example.com", { all: true });
    expect(err).toBeNull();
    expect(address).toEqual([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800::1", family: 6 },
    ]);
  });

  it("serves the first pinned address (single form) and matches case-insensitively", async () => {
    const { err, address, family } = await callLookup("API.EXAMPLE.COM", {});
    expect(err).toBeNull();
    expect(address).toBe("93.184.216.34");
    expect(family).toBe(4);
  });

  it("honors a requested address family", async () => {
    const { err, address, family } = await callLookup("api.example.com", { family: 6 });
    expect(err).toBeNull();
    expect(address).toBe("2606:2800::1");
    expect(family).toBe(6);
  });

  it("errors when no pinned address matches the requested family", async () => {
    const v4Only = new Map<string, readonly string[]>([["v4.example.com", ["93.184.216.34"]]]);
    await new Promise<void>((resolve) => {
      createPinnedLookup(v4Only)("v4.example.com", { family: 6 }, (err) => {
        expect(err?.code).toBe("ENOTFOUND");
        resolve();
      });
    });
  });

  it("delegates unpinned hostnames to the system resolver (loopback only)", async () => {
    const { err, address } = await callLookup("localhost", {});
    expect(err).toBeNull();
    expect(address).toBeDefined();
  });
});
