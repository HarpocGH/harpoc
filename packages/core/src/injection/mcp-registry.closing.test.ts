import { describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import type { McpConnectionEntry } from "./mcp-registry.js";
import { McpConnectionRegistry } from "./mcp-registry.js";
import type { StdioChildTransport } from "./mcp-stdio-transport.js";

function fakeEntry(secretId: string, close: () => Promise<void>): McpConnectionEntry {
  return {
    secretId,
    serverName: "slot-mcp",
    transportKind: "stdio",
    client: { close } as never,
    state: "connecting",
    crashed: false,
    credentialFingerprint: "f",
    configFingerprint: "g",
    isolation: { network: false, fs: false },
    strictTreeExit: false,
    spawnedAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

function recordingLogger(): { logger: AuditLogger; rows: AuditLogOptions[] } {
  const rows: AuditLogOptions[] = [];
  const logger = {
    log: (options: AuditLogOptions) => {
      rows.push(options);
    },
  } as unknown as AuditLogger;
  return { logger, rows };
}

function fakeStdio(
  exitInfo: StdioChildTransport["exitInfo"],
  killSync: () => void = vi.fn(),
): StdioChildTransport {
  return {
    exitInfo,
    killSync,
    stderrTail: { toString: () => "" },
  } as unknown as StdioChildTransport;
}

function gate(): { promise: Promise<void>; open: () => void } {
  let open: () => void = () => undefined;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

function liveOf(registry: McpConnectionRegistry): Map<string, McpConnectionEntry> {
  return (registry as unknown as { live: Map<string, McpConnectionEntry> }).live;
}

function freshFactory(secretId: string): () => Promise<McpConnectionEntry> {
  return vi.fn(() => Promise.resolve(fakeEntry(secretId, vi.fn().mockResolvedValue(undefined))));
}

describe("McpConnectionRegistry — while it closes", () => {
  it("an entry published during closeAll's wait is killed", async () => {
    const { logger, rows } = recordingLogger();
    const registry = new McpConnectionRegistry(logger);
    const held = gate();
    await registry.acquire("s1", () => Promise.resolve(fakeEntry("s1", () => held.promise)));
    const closing = registry.closeAll("vault_lock");
    const killLate = vi.fn();
    liveOf(registry).set("s2", {
      ...fakeEntry("s2", vi.fn().mockResolvedValue(undefined)),
      stdioTransport: fakeStdio(null, killLate),
      state: "ready",
    });

    held.open();
    await closing;

    expect(killLate).toHaveBeenCalledTimes(1);
    expect(rows.map((row) => [row.eventType, row.secretId])).toEqual([
      [AuditEventType.MCP_TERMINATE, "s1"],
    ]);
  });

  it("acquire is refused while the registry closes", async () => {
    const registry = new McpConnectionRegistry(null);
    const held = gate();
    await registry.acquire("s1", () => Promise.resolve(fakeEntry("s1", () => held.promise)));
    const closing = registry.closeAll("vault_lock");
    const factory = freshFactory("s");

    await expectVaultError(() => registry.acquire("s", factory), ErrorCode.VAULT_LOCKED);

    expect(factory).not.toHaveBeenCalled();
    held.open();
    await closing;
  });

  it("acquire works again after closeAll", async () => {
    const registry = new McpConnectionRegistry(null);
    await registry.acquire("s1", () =>
      Promise.resolve(fakeEntry("s1", vi.fn().mockResolvedValue(undefined))),
    );
    await registry.closeAll("vault_lock");
    const factory = freshFactory("s1");

    const entry = await registry.acquire("s1", factory);

    expect(factory).toHaveBeenCalledTimes(1);
    expect(registry.get("s1")).toBe(entry);
    await registry.closeAll("test_cleanup");
  });

  it("killAllSync during closeAll's wait keeps acquire refused", async () => {
    const registry = new McpConnectionRegistry(null);
    const held = gate();
    await registry.acquire("s1", () => Promise.resolve(fakeEntry("s1", () => held.promise)));
    const closing = registry.closeAll("vault_lock");
    registry.killAllSync();
    held.open();
    await closing;
    const factory = freshFactory("s");

    await expectVaultError(() => registry.acquire("s", factory), ErrorCode.VAULT_LOCKED);

    expect(factory).not.toHaveBeenCalled();
  });

  it("a second closeAll that is still waiting keeps acquire refused when the first ends", async () => {
    const registry = new McpConnectionRegistry(null);
    const first = gate();
    const second = gate();
    await registry.acquire("s1", () => Promise.resolve(fakeEntry("s1", () => first.promise)));
    const firstClosing = registry.closeAll("vault_lock");
    liveOf(registry).set("s2", { ...fakeEntry("s2", () => second.promise), state: "ready" });
    const secondClosing = registry.closeAll("engine_destroy");
    first.open();
    await firstClosing;
    const factory = freshFactory("s");

    await expectVaultError(() => registry.acquire("s", factory), ErrorCode.VAULT_LOCKED);

    expect(factory).not.toHaveBeenCalled();
    second.open();
    await secondClosing;
    await registry.acquire("s", factory);
    expect(factory).toHaveBeenCalledTimes(1);
    await registry.closeAll("test_cleanup");
  });

  it("a closeAll that begins and ends during another's wait keeps acquire refused until the other ends", async () => {
    const registry = new McpConnectionRegistry(null);
    const held = gate();
    await registry.acquire("s1", () => Promise.resolve(fakeEntry("s1", () => held.promise)));
    const closing = registry.closeAll("vault_lock");
    await registry.closeAll("engine_destroy");
    const factory = freshFactory("s");

    await expectVaultError(() => registry.acquire("s", factory), ErrorCode.VAULT_LOCKED);

    expect(factory).not.toHaveBeenCalled();
    held.open();
    await closing;
    const entry = await registry.acquire("s", factory);
    expect(factory).toHaveBeenCalledTimes(1);
    expect(registry.get("s")).toBe(entry);
    await registry.closeAll("test_cleanup");
  });

  it("closeAll after killAllSync keeps acquire refused", async () => {
    const registry = new McpConnectionRegistry(null);
    registry.killAllSync();
    await registry.closeAll("engine_destroy");
    const factory = freshFactory("s");

    await expectVaultError(() => registry.acquire("s", factory), ErrorCode.VAULT_LOCKED);

    expect(factory).not.toHaveBeenCalled();
  });

  it("acquire is refused after killAllSync", async () => {
    const registry = new McpConnectionRegistry(null);
    registry.killAllSync();
    const factory = freshFactory("s1");

    await expectVaultError(() => registry.acquire("s1", factory), ErrorCode.VAULT_LOCKED);

    expect(factory).not.toHaveBeenCalled();
  });
});
