import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";

// Partial mock: hostnames under *.pinned.test validate successfully and pin to
// the loopback downstream server; everything else uses the real validator. The
// .test TLD never resolves in real DNS — a request to these hosts can only
// succeed if the pinned dispatcher drives the connection.
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

import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

const SECRET = "sk-mcp-http-secret-0123456789";

const POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
};

function mcpAction(tool: string): McpAction {
  return { type: "mcp", server: "http-mcp", tool };
}

function httpConfig(url: string): McpServerConfig {
  return { server_name: "http-mcp", transport: "http", url };
}

function run(injector: McpInjector, config: McpServerConfig, tool = "echo") {
  return injector.executeWithSecret(
    mcpAction(tool),
    new Uint8Array(Buffer.from(SECRET, "utf8")),
    POLICY,
    config,
    "secret-http-1",
  );
}

describe("MCP Streamable HTTP DNS-rebinding pinning", () => {
  let httpServer: Server;
  let port: number;
  let registry: McpConnectionRegistry;
  const seenHosts: (string | undefined)[] = [];

  beforeEach(async () => {
    seenHosts.length = 0;
    const downstream = new McpServer({ name: "pinned-downstream", version: "1.0.0" });
    downstream.tool("echo", "Echo a fixed marker", {}, async () => ({
      content: [{ type: "text" as const, text: "pinned-ok" }],
    }));
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });
    await downstream.connect(transport);

    httpServer = createServer((req, res) => {
      seenHosts.push(req.headers.host);
      void transport.handleRequest(req, res);
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    port = (httpServer.address() as AddressInfo).port;
    registry = new McpConnectionRegistry(null);
  });

  afterEach(async () => {
    await registry.closeAll();
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  it("connects through the pinned address while preserving the logical hostname", async () => {
    const injector = new McpInjector(null, registry);
    const result = await run(injector, httpConfig(`http://mcp.pinned.test:${port}/mcp`));

    expect(JSON.stringify(result.content)).toContain("pinned-ok");
    expect(seenHosts.length).toBeGreaterThan(0);
    expect(seenHosts.every((h) => h === `mcp.pinned.test:${port}`)).toBe(true);
  });
});

describe("MCP Streamable HTTP redirect refusal", () => {
  let redirectServer: Server;
  let victimServer: Server;
  let redirectPort: number;
  let victimHits: number;
  let registry: McpConnectionRegistry;

  beforeEach(async () => {
    victimHits = 0;
    victimServer = createServer((_req, res) => {
      victimHits++;
      res.end("{}");
    });
    await new Promise<void>((resolve) => victimServer.listen(0, "127.0.0.1", resolve));
    const victimPort = (victimServer.address() as AddressInfo).port;

    redirectServer = createServer((_req, res) => {
      res.writeHead(307, { location: `http://127.0.0.1:${victimPort}/mcp` });
      res.end();
    });
    await new Promise<void>((resolve) => redirectServer.listen(0, "127.0.0.1", resolve));
    redirectPort = (redirectServer.address() as AddressInfo).port;
    registry = new McpConnectionRegistry(null);
  });

  afterEach(async () => {
    await registry.closeAll();
    await new Promise<void>((resolve) => redirectServer.close(() => resolve()));
    await new Promise<void>((resolve) => victimServer.close(() => resolve()));
  });

  it("refuses a downstream redirect and never contacts its target", async () => {
    const injector = new McpInjector(null, registry);
    await expect(
      run(injector, httpConfig(`http://127.0.0.1:${redirectPort}/mcp`)),
    ).rejects.toMatchObject({ code: ErrorCode.REDIRECT_POLICY_VIOLATION });
    expect(victimHits).toBe(0);
  });
});
