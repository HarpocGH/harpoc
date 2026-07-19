import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  DatabaseAction,
  GitAction,
  InjectionPolicy,
  McpAction,
  McpServerConfig,
  ProcessAction,
  SshAction,
} from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { DatabaseInjector } from "./database-injector.js";
import type { DbEngineAdapter } from "./db-adapters.js";
import { GitInjector } from "./git-injector.js";
import { HttpInjector } from "./http-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";
import { McpInjector } from "./mcp-injector.js";
import { ProcessInjector } from "./process-injector.js";
import { SshInjector } from "./ssh-injector.js";

const NODE = process.execPath;
const SECRET = new Uint8Array(Buffer.from("attr-secret-value-123456", "utf8"));

const ATTRIBUTION: AuditAttribution = {
  principal_type: "agent",
  principal_id: "alice",
  session_id: "sess-attr-1",
  interface: "rest",
};

const EMPTY_POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
};

function captureLogger(): { log: ReturnType<typeof vi.fn>; logger: AuditLogger } {
  const log = vi.fn();
  return { log, logger: { log } as unknown as AuditLogger };
}

function rows(log: ReturnType<typeof vi.fn>): AuditLogOptions[] {
  return log.mock.calls.map((c) => c[0] as AuditLogOptions);
}

/** The attributed shape every injector row must carry (columns + detail.interface). */
function expectAttributed(row: AuditLogOptions): void {
  expect(row.principalType).toBe("agent");
  expect(row.principalId).toBe("alice");
  expect(row.sessionId).toBe("sess-attr-1");
  expect(row.detail?.interface).toBe("rest");
}

/** The trusted-local pin: no principal columns, no interface in detail. */
function expectUnattributed(row: AuditLogOptions): void {
  expect(row.principalType).toBeUndefined();
  expect(row.principalId).toBeUndefined();
  expect(row.detail && "interface" in row.detail).toBe(false);
}

describe("ProcessInjector attribution", () => {
  const action: ProcessAction = { type: "process", command: NODE, env_var: "SECRET" };

  it("stamps the success row with principal, session and interface", async () => {
    const { log, logger } = captureLogger();
    const injector = new ProcessInjector(logger);
    await injector.executeWithSecret(
      { ...action, args: ["-e", "process.exit(0)"] },
      SECRET,
      { command_allowlist: [NODE], env_allowlist: [] },
      "secret-1",
      ATTRIBUTION,
    );
    const [row] = rows(log);
    expect(row?.eventType).toBe("secret.use");
    expect(row?.success).not.toBe(false);
    expectAttributed(row as AuditLogOptions);
  });

  it("stamps the allowlist-denial row too", async () => {
    const { log, logger } = captureLogger();
    const injector = new ProcessInjector(logger);
    await expect(
      injector.executeWithSecret(
        action,
        SECRET,
        { command_allowlist: [], env_allowlist: [] },
        "secret-1",
        ATTRIBUTION,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
    const [row] = rows(log);
    expect(row?.success).toBe(false);
    expectAttributed(row as AuditLogOptions);
  });

  it("writes NULL-principal rows without attribution (trusted local pin)", async () => {
    const { log, logger } = captureLogger();
    const injector = new ProcessInjector(logger);
    await injector.executeWithSecret(
      { ...action, args: ["-e", "process.exit(0)"] },
      SECRET,
      { command_allowlist: [NODE], env_allowlist: [] },
      "secret-1",
    );
    expectUnattributed(rows(log)[0] as AuditLogOptions);
  });
});

describe("SshInjector attribution", () => {
  it("stamps the host-allowlist denial row", async () => {
    const { log, logger } = captureLogger();
    const injector = new SshInjector(logger);
    const action: SshAction = { type: "ssh", host: "host.example.com", user: "deploy" };
    await expect(
      injector.executeWithSecret(action, SECRET, EMPTY_POLICY, undefined, "secret-1", ATTRIBUTION),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    const [row] = rows(log);
    expect(row?.detail?.error).toBe("HOST_NOT_ALLOWED");
    expectAttributed(row as AuditLogOptions);
  });
});

describe("GitInjector attribution", () => {
  it("stamps the unsupported-transport denial row", async () => {
    const { log, logger } = captureLogger();
    const injector = new GitInjector(logger);
    const action: GitAction = {
      type: "git",
      operation: "clone",
      repository: "ext::sh -c whoami",
    };
    await expect(
      injector.executeWithSecret(action, SECRET, EMPTY_POLICY, undefined, "secret-1", ATTRIBUTION),
    ).rejects.toMatchObject({ code: ErrorCode.GIT_UNSUPPORTED_TRANSPORT });
    const [row] = rows(log);
    expect(row?.detail?.error).toBe("GIT_UNSUPPORTED_TRANSPORT");
    expectAttributed(row as AuditLogOptions);
  });
});

describe("DatabaseInjector attribution", () => {
  const action: DatabaseAction = {
    type: "database",
    engine: "postgres",
    host: "8.8.8.8",
    database: "app",
    query: "SELECT 1",
  };

  it("stamps the success row (fake adapter, no real dial)", async () => {
    const { log, logger } = captureLogger();
    const adapter: DbEngineAdapter = {
      connect: async () => ({
        query: async () => ({ rows: [{ ok: 1 }], fields: [{ name: "ok" }], rowCount: 1 }),
        end: async () => undefined,
      }),
    };
    const injector = new DatabaseInjector(logger, { postgres: adapter });
    await injector.executeWithSecret(
      action,
      new Uint8Array(Buffer.from("dbuser:dbpassword", "utf8")),
      EMPTY_POLICY,
      undefined,
      "secret-1",
      ATTRIBUTION,
    );
    const [row] = rows(log);
    expect(row?.detail?.row_count).toBe(1);
    expectAttributed(row as AuditLogOptions);
  });

  it("stamps the unsupported-engine denial row", async () => {
    const { log, logger } = captureLogger();
    const injector = new DatabaseInjector(logger, {});
    await expect(
      injector.executeWithSecret(
        action,
        new Uint8Array(Buffer.from("dbuser:dbpassword", "utf8")),
        EMPTY_POLICY,
        undefined,
        "secret-1",
        ATTRIBUTION,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.UNSUPPORTED_DB_ENGINE });
    expectAttributed(rows(log)[0] as AuditLogOptions);
  });
});

describe("HttpInjector attribution", () => {
  it("stamps the success row on a loopback request", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const { log, logger } = captureLogger();
      const injector = new HttpInjector(logger);
      const result = await injector.executeWithSecret(
        { method: "GET", url: `http://127.0.0.1:${port}/` },
        SECRET,
        { type: "bearer" },
        "same-origin",
        "secret-1",
        ATTRIBUTION,
      );
      expect(result.status).toBe(200);
      const [row] = rows(log);
      expect(row?.detail?.status).toBe(200);
      expectAttributed(row as AuditLogOptions);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("McpInjector attribution (incl. D5 lifecycle pins)", () => {
  // Minimal newline-delimited JSON-RPC downstream: initialize, echo, crash.
  const TEST_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "attr-test-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    if (m.params.name === "crash") { process.exit(7); }
    send({ jsonrpc: "2.0", id: m.id, result: {
      content: [{ type: "text", text: "done" }],
    }});
  }
});
`;

  const CONFIG: McpServerConfig = {
    server_name: "attr-mcp",
    transport: "stdio",
    command: NODE,
    args: ["-e", TEST_SERVER],
    env_var: "DOWNSTREAM_TOKEN",
  };

  const POLICY: InjectionPolicy = { ...EMPTY_POLICY, command_allowlist: [NODE] };

  let registry: McpConnectionRegistry | null = null;

  afterEach(async () => {
    await registry?.closeAll("test_cleanup");
    registry = null;
  });

  function mcpAction(tool: string, server = "attr-mcp"): McpAction {
    return { type: "mcp", server, tool };
  }

  it("stamps the server-mismatch denial row (no spawn)", async () => {
    const { log, logger } = captureLogger();
    registry = new McpConnectionRegistry(logger);
    const injector = new McpInjector(logger, registry);
    await expect(
      injector.executeWithSecret(
        mcpAction("echo", "other-mcp"),
        SECRET,
        POLICY,
        CONFIG,
        "secret-1",
        ATTRIBUTION,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.MCP_SERVER_MISMATCH });
    expectAttributed(rows(log)[0] as AuditLogOptions);
  });

  it("attributes mcp.spawn and the secret.use success; crash and terminate rows stay unattributed (D5)", async () => {
    const { log, logger } = captureLogger();
    registry = new McpConnectionRegistry(logger);
    const injector = new McpInjector(logger, registry);

    await injector.executeWithSecret(
      mcpAction("echo"),
      SECRET,
      POLICY,
      CONFIG,
      "secret-1",
      ATTRIBUTION,
    );

    const afterSuccess = rows(log);
    const spawn = afterSuccess.find((r) => r.eventType === "mcp.spawn");
    const use = afterSuccess.find((r) => r.eventType === "secret.use");
    expect(spawn).toBeDefined();
    expectAttributed(spawn as AuditLogOptions);
    expectAttributed(use as AuditLogOptions);

    // Crash mid-call: the child-exit row has no requesting principal (D5).
    await expect(
      injector.executeWithSecret(
        mcpAction("crash"),
        SECRET,
        POLICY,
        CONFIG,
        "secret-1",
        ATTRIBUTION,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.MCP_SERVER_CRASHED });
    const crash = rows(log).find((r) => r.eventType === "mcp.crash");
    expect(crash).toBeDefined();
    expectUnattributed(crash as AuditLogOptions);

    // Vault-initiated terminate: unattributed too (D5).
    await injector.executeWithSecret(
      mcpAction("echo"),
      SECRET,
      POLICY,
      CONFIG,
      "secret-1",
      ATTRIBUTION,
    );
    await registry.closeAll("session_end");
    const terminate = rows(log).find((r) => r.eventType === "mcp.terminate");
    expect(terminate).toBeDefined();
    expectUnattributed(terminate as AuditLogOptions);
  });
});
