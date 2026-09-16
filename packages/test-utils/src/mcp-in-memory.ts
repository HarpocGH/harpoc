import { Client } from "@modelcontextprotocol/client";
import type { ClientOptions, Implementation } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import type { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { McpProtocolRevision } from "@harpoc/shared";

export interface InMemoryToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface InMemoryToolDescriptor {
  name: string;
  description?: string;
  inputSchema: { properties?: Record<string, unknown> };
}

export interface InMemoryMcpClient {
  readonly client: Client;
  callTool(name: string, args: Record<string, unknown>): Promise<InMemoryToolResult>;
  listTools(): Promise<InMemoryToolDescriptor[]>;
  readResource(
    uri: string,
  ): Promise<{ contents: Array<{ uri: string; mimeType?: string; text?: string }> }>;
  /** Closes the client, then the server. */
  close(): Promise<void>;
}

/**
 * A real MCP client over the SDK's linked in-memory pair: what the test suites
 * used to do by reaching into the server's private handler map, on the wire the
 * SDK itself owns. A tool handler's throw arrives as an `isError` result, a
 * refused argument as the SDK's own validation text — both as a host would see
 * them.
 */
export async function connectInMemoryClient(
  server: McpServer,
  clientInfo: { name: string; version: string } = { name: "test-client", version: "0.0.0" },
  clientOptions?: ConstructorParameters<typeof Client>[1],
): Promise<InMemoryMcpClient> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client(clientInfo, clientOptions);
  await client.connect(clientTransport);
  return wrapClient(client, async () => {
    clients.delete(server);
    try {
      await client.close();
    } finally {
      await server.close();
    }
  });
}

function wrapClient(client: Client, close: () => Promise<void>): InMemoryMcpClient {
  return {
    client,
    async callTool(name, args) {
      return (await client.callTool({ name, arguments: args })) as InMemoryToolResult;
    },
    async listTools() {
      return (await client.listTools()).tools as InMemoryToolDescriptor[];
    },
    async readResource(uri) {
      return (await client.readResource({ uri })) as {
        contents: Array<{ uri: string; mimeType?: string; text?: string }>;
      };
    },
    close,
  };
}

/**
 * A client pinned to the 2026-07-28 revision over an in-memory pair. The
 * bare pair cannot serve the modern era (a plain McpServer answers
 * server/discover with -32601); serveStdio owns the era decision for the
 * connection and pins one instance from the factory, so the same factory
 * that builds the vault's server serves a modern client here.
 */
export async function connectModernInMemoryClient(
  factory: () => McpServer,
  clientInfo: Implementation = { name: "harpoc-test-client", version: "1.0.0" },
  clientOptions: ClientOptions = {},
): Promise<InMemoryMcpClient> {
  const [clientEnd, serverEnd] = InMemoryTransport.createLinkedPair();
  const handle = serveStdio(factory, { transport: serverEnd });
  const client = new Client(clientInfo, {
    ...clientOptions,
    versionNegotiation: { mode: { pin: McpProtocolRevision.MODERN } },
  });
  try {
    await client.connect(clientEnd);
  } catch (err) {
    await handle.close().catch(() => undefined);
    throw err;
  }
  return wrapClient(client, async () => {
    await client.close().catch(() => undefined);
    await handle.close().catch(() => undefined);
  });
}

const clients = new WeakMap<McpServer, Promise<InMemoryMcpClient>>();

/** One connected client per server object, for helpers called once per test call. */
export function inMemoryClientFor(server: McpServer): Promise<InMemoryMcpClient> {
  let pending = clients.get(server);
  if (!pending) {
    pending = connectInMemoryClient(server);
    clients.set(server, pending);
    pending.catch(() => {
      clients.delete(server);
    });
  }
  return pending;
}

/**
 * The one place a test may reach a registered handler directly — for the
 * assertions that need a resource handler's thrown VaultError intact (on the
 * wire the SDK renders it as a ProtocolError -32603 carrying the message only).
 * The vault's handlers read nothing from the context object.
 */
export async function invokeHandler(
  server: McpServer,
  method: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const lowLevel = (server as unknown as { server: { _requestHandlers: Map<string, unknown> } })
    .server;
  const handler = lowLevel._requestHandlers.get(method) as
    | ((
        request: { method: string; params: Record<string, unknown> },
        ctx: unknown,
      ) => Promise<unknown>)
    | undefined;
  if (!handler) throw new Error(`No ${method} handler registered`);
  return handler(
    { method, params },
    {
      sessionId: "test",
      mcpReq: {
        id: 1,
        method,
        requestState: () => undefined,
        signal: new AbortController().signal,
      },
    },
  );
}
