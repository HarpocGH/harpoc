import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { VaultEngine } from "@harpoc/core";
import { AuditEventType, SESSION_FILE_NAME, VAULT_DB_NAME } from "@harpoc/shared";
import { registerAgents } from "./helpers/engine-factory.js";
import { CLI_ENTRY, runCli } from "./helpers/spawn-cli.js";

const PASSWORD = "dual-era-stdio-pw";
const LEGACY_VERSION = "2025-11-25";
const MODERN_VERSION = "2026-07-28";
const TOOL_COUNT = 9;
const MAX_STDERR_TAIL_CHARS = 2_048;

const MCP_ENTRY = join(
  dirname(createRequire(import.meta.url).resolve("@harpoc/mcp-server/package.json")),
  "dist",
  "index.js",
);

/**
 * The SDK's stdio transport runs a pinned connect's discover probe on a
 * disposable sibling process — a second vault process, a second server.start
 * row. A subclass probes in place (the SDK's documented rule), so each case
 * spawns the entry exactly once.
 */
class InPlaceStdioClientTransport extends StdioClientTransport {}

interface Connected {
  client: Client;
  close(): Promise<void>;
}

describe("both protocol eras on one stdio pipe", () => {
  let vaultDir: string;
  let engine: VaultEngine;

  function childEnv(): Record<string, string> {
    const env: Record<string, string> = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (value !== undefined) env[key] = value;
    }
    delete env["HARPOC_TOKEN"];
    return env;
  }

  function tokenFileFor(agent: string): string {
    registerAgents(engine, agent);
    const token = engine.createToken(agent, ["read", "list"]);
    const path = join(vaultDir, `launch-token-${agent}`);
    writeFileSync(path, `${token}\n`, { encoding: "utf8", mode: 0o600 });
    return path;
  }

  async function connectStdio(options: {
    name: string;
    args: string[];
    pinned: boolean;
  }): Promise<Connected> {
    const params = {
      command: process.execPath,
      args: options.args,
      env: childEnv(),
      stderr: "pipe" as const,
    };
    const transport = options.pinned
      ? new InPlaceStdioClientTransport(params)
      : new StdioClientTransport(params);
    let stderr = "";
    transport.stderr?.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
    const client = options.pinned
      ? new Client(
          { name: options.name, version: "1.0.0" },
          { versionNegotiation: { mode: { pin: MODERN_VERSION } } },
        )
      : new Client({ name: options.name, version: "1.0.0" });
    try {
      await client.connect(transport);
    } catch (err) {
      await transport.close().catch(() => undefined);
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(
        [
          `${options.name} could not connect: ${reason}`,
          `child stderr: ${stderr.slice(-MAX_STDERR_TAIL_CHARS)}`,
        ].join("\n"),
        { cause: err },
      );
    }
    return {
      client,
      async close() {
        try {
          await client.close();
        } finally {
          await transport.close();
        }
      },
    };
  }

  async function assertModernSession(connected: Connected): Promise<void> {
    expect(connected.client.getNegotiatedProtocolVersion()).toBe(MODERN_VERSION);
    const tools = await connected.client.listTools();
    expect(tools.tools).toHaveLength(TOOL_COUNT);
    const result = await connected.client.callTool({ name: "list_secrets", arguments: {} });
    expect(result.isError).not.toBe(true);
  }

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-dual-era-"));
    const init = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    await init.initVault(PASSWORD);
    await init.destroy();
    const unlock = await runCli(["unlock"], { vaultDir, stdin: `${PASSWORD}\n` });
    expect(unlock.code).toBe(0);
    engine = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    expect(await engine.loadSession()).toBe(true);
  }, 120_000);

  afterAll(async () => {
    await engine.destroy();
    rmSync(vaultDir, { recursive: true, force: true });
  });

  it("a 2025-era client over harpoc-mcp negotiates 2025-11-25 and lists the nine tools", async () => {
    const tokenFile = tokenFileFor("dual-era-legacy");
    const connected = await connectStdio({
      name: "harpoc-dual-era-legacy-client",
      args: [MCP_ENTRY, "--vault-dir", vaultDir, "--token-file", tokenFile],
      pinned: false,
    });
    try {
      expect(connected.client.getNegotiatedProtocolVersion()).toBe(LEGACY_VERSION);
      const tools = await connected.client.listTools();
      expect(tools.tools).toHaveLength(TOOL_COUNT);
    } finally {
      await connected.close();
    }
  });

  it("a 2026-07-28 client over harpoc-mcp negotiates the modern era and calls a tool", async () => {
    const tokenFile = tokenFileFor("dual-era-modern");
    const connected = await connectStdio({
      name: "harpoc-dual-era-modern-client",
      args: [MCP_ENTRY, "--vault-dir", vaultDir, "--token-file", tokenFile],
      pinned: true,
    });
    try {
      await assertModernSession(connected);
    } finally {
      await connected.close();
    }
  });

  it("the modern connect spawned the entry exactly once: one server.start row", () => {
    const starts = engine
      .queryAudit({ eventType: AuditEventType.SERVER_START })
      .filter((row) => row.detail?.subject === "dual-era-modern");
    expect(starts).toHaveLength(1);
    expect(starts[0]?.detail).toMatchObject({ transport: "stdio", tokenless: false });
  });

  it("a 2026-07-28 client over harpoc server start --mcp negotiates the modern era", async () => {
    const tokenFile = tokenFileFor("dual-era-cli");
    const connected = await connectStdio({
      name: "harpoc-dual-era-cli-client",
      args: [
        CLI_ENTRY,
        "--vault-dir",
        vaultDir,
        "server",
        "start",
        "--mcp",
        "--token-file",
        tokenFile,
      ],
      pinned: true,
    });
    try {
      await assertModernSession(connected);
    } finally {
      await connected.close();
    }
  });
});
