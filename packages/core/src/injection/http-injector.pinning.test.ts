import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Partial mock: hostnames under *.pinned.test validate successfully and pin to
// the loopback test server; everything else uses the real validator. The .test
// TLD never resolves in real DNS — a request to these hosts can only succeed
// if the pinned lookup drives the connection.
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(async (urlStr: string) => {
      const url = new URL(urlStr);
      if (url.hostname.endsWith(".pinned.test")) {
        return { url, resolvedAddresses: ["127.0.0.1"] };
      }
      return actual.validateUrl(urlStr);
    }),
  };
});

import { HttpInjector, createPinnedLookup } from "./http-injector.js";

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
      { method: "GET", url: `http://a.pinned.test:${port}/hop` },
      new TextEncoder().encode("pin-secret"),
      { type: "bearer" },
      "any",
    );

    expect(result.status).toBe(200);
    expect(requests.map((r) => r.host)).toEqual([`a.pinned.test:${port}`, `b.pinned.test:${port}`]);
    expect(requests.at(1)?.url).toBe("/final");
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
