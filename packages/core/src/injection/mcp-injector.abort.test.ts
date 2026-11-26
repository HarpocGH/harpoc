import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { fetch as undiciFetch } from "undici";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import {
  POLICY,
  STDIO_CONFIG,
  TEST_SERVER,
  mcpAction,
  secretBytes,
} from "./__fixtures__/mcp-downstream.js";
import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";
import { StdioChildTransport } from "./mcp-stdio-transport.js";
import { validateUrl } from "./url-validator.js";

vi.mock("./mcp-stdio-transport.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./mcp-stdio-transport.js")>();
  return {
    ...actual,
    StdioChildTransport: vi.fn(function (
      params: ConstructorParameters<typeof actual.StdioChildTransport>[0],
    ) {
      return new actual.StdioChildTransport(params);
    }),
  };
});

vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return { ...actual, validateUrl: vi.fn(actual.validateUrl) };
});

vi.mock("undici", async (importOriginal) => {
  const actual = await importOriginal<typeof import("undici")>();
  return { ...actual, fetch: vi.fn(actual.fetch) };
});

const actual = await vi.importActual<typeof import("./mcp-stdio-transport.js")>(
  "./mcp-stdio-transport.js",
);
const actualValidator =
  await vi.importActual<typeof import("./url-validator.js")>("./url-validator.js");
const construct = vi.mocked(StdioChildTransport);

/** A downstream that never answers its handshake. */
const SILENT_CONFIG: McpServerConfig = { ...STDIO_CONFIG, args: ["-e", "process.stdin.resume()"] };

let dir: string;
let registry: McpConnectionRegistry;
let injector: McpInjector;

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw err;
  }
}

function quiet<T>(promise: Promise<T>): Promise<T> {
  promise.catch(() => undefined);
  return promise;
}

function run(signal: AbortSignal, config: McpServerConfig): Promise<unknown> {
  return injector.executeWithSecret(
    mcpAction("echo"),
    secretBytes(),
    POLICY,
    config,
    "secret-1",
    undefined,
    signal,
  );
}

/** Resolves with the child's pid once its handshake's first message is written. */
function handshakeBegun(): Promise<number> {
  const send = actual.StdioChildTransport.prototype.send;
  return new Promise((resolve) => {
    vi.spyOn(actual.StdioChildTransport.prototype, "send").mockImplementation(function (
      this: StdioChildTransport,
      message,
    ) {
      if ((message as { method?: unknown }).method === "initialize") resolve(this.pid as number);
      return send.call(this, message);
    });
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harpoc-mcp-abort-"));
  registry = new McpConnectionRegistry(null);
  injector = new McpInjector(null, registry);
  construct.mockClear();
  vi.mocked(validateUrl).mockClear();
  vi.mocked(undiciFetch).mockClear();
});

afterEach(async () => {
  vi.restoreAllMocks();
  for (const built of construct.mock.results) (built.value as StdioChildTransport).killSync();
  await registry.closeAll("test_cleanup");
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("McpInjector — the use's abort signal", () => {
  it("an already-aborted signal starts no child: VAULT_LOCKED, no transport built", async () => {
    const marker = join(dir, "started");
    const marking: McpServerConfig = {
      ...STDIO_CONFIG,
      args: [
        "-e",
        `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "");${TEST_SERVER}`,
      ],
    };
    const controller = new AbortController();
    controller.abort();

    await expectVaultError(() => run(controller.signal, marking), ErrorCode.VAULT_LOCKED);

    expect(construct.mock.calls.length).toBe(0);
    expect(existsSync(marker)).toBe(false);
  });

  it("an abort during the handshake kills the child being connected and answers VAULT_LOCKED", async () => {
    const kill = vi.spyOn(actual.StdioChildTransport.prototype, "killSync");
    const begun = handshakeBegun();
    const controller = new AbortController();
    const call = quiet(run(controller.signal, SILENT_CONFIG));
    const pid = await Promise.race([begun, call]);

    controller.abort();

    expect(kill).toHaveBeenCalledTimes(1);
    await expectVaultError(() => call, ErrorCode.VAULT_LOCKED);
    expect(isAlive(pid as number)).toBe(false);
  });

  it("an abort during an http connect's address lookup sends no request and answers VAULT_LOCKED", async () => {
    let requests = 0;
    const server = createServer((_req, res) => {
      requests += 1;
      res.writeHead(503);
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const config: McpServerConfig = {
        server_name: "test-mcp",
        transport: "http",
        protocol: "2025-11-25",
        url: `${origin}/mcp`,
      };
      const controller = new AbortController();
      vi.mocked(validateUrl)
        .mockImplementationOnce(actualValidator.validateUrl)
        .mockImplementationOnce(async (url) => {
          controller.abort();
          return actualValidator.validateUrl(url);
        });

      await expectVaultError(
        () =>
          injector.executeWithSecret(
            mcpAction("echo"),
            secretBytes(),
            { ...POLICY, url_allowlist: [`${origin}/*`] },
            config,
            "secret-1",
            undefined,
            controller.signal,
          ),
        ErrorCode.VAULT_LOCKED,
      );

      expect(vi.mocked(validateUrl)).toHaveBeenCalledTimes(2);
      expect(vi.mocked(undiciFetch)).not.toHaveBeenCalled();
      expect(requests).toBe(0);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("an abort while an http connect waits for its answer ends the client being connected and answers VAULT_LOCKED", async () => {
    let arrive: () => void = () => undefined;
    const arrived = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    const server = createServer(() => arrive());
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const close = vi.spyOn(Client.prototype, "close");
      const controller = new AbortController();
      const call = quiet(
        injector.executeWithSecret(
          mcpAction("echo"),
          secretBytes(),
          { ...POLICY, url_allowlist: [`${origin}/*`] },
          {
            server_name: "test-mcp",
            transport: "http",
            protocol: "2025-11-25",
            url: `${origin}/mcp`,
          },
          "secret-1",
          undefined,
          controller.signal,
        ),
      );
      await Promise.race([arrived, call]);

      controller.abort();

      expect(close).toHaveBeenCalledTimes(1);
      await expectVaultError(() => call, ErrorCode.VAULT_LOCKED);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
