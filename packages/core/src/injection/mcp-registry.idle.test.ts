import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, MCP_IDLE_SWEEP_INTERVAL_MS, MCP_IDLE_TTL_MS } from "@harpoc/shared";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import type { McpConnectionEntry } from "./mcp-registry.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

const TTL = 1_000;
const SWEEP = 100;

function recordingLogger(): { logger: AuditLogger; rows: AuditLogOptions[] } {
  const rows: AuditLogOptions[] = [];
  const logger = {
    log: (options: AuditLogOptions) => {
      rows.push(options);
    },
  } as unknown as AuditLogger;
  return { logger, rows };
}

function fakeEntry(secretId: string, close: () => Promise<void>): McpConnectionEntry {
  return {
    secretId,
    serverName: "idle-mcp",
    transportKind: "stdio",
    client: { close } as never,
    state: "connecting",
    crashed: false,
    credentialFingerprint: "f",
    configFingerprint: "g",
    spawnedAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

describe("McpConnectionRegistry — idle TTL defaults (E73)", () => {
  it("defaults: ten minutes idle, a thirty-second sweep", () => {
    expect(MCP_IDLE_TTL_MS).toBe(600_000);
    expect(MCP_IDLE_SWEEP_INTERVAL_MS).toBe(30_000);
  });
});

// E73: a downstream child holds the injected credential in its environment for
// as long as it lives. Nothing bounded that lifetime between uses — a child
// spawned once stayed until the session ended. These run on fake timers: the
// sweep is an unref'd interval and Date.now() is the clock it reads.
describe("McpConnectionRegistry — idle TTL (E73)", () => {
  let registry: McpConnectionRegistry;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(async () => {
    await registry.closeAll("test_cleanup");
    vi.useRealTimers();
  });

  it("terminates an entry no acquire has touched for the TTL — reason idle, unattributed", async () => {
    const { logger, rows } = recordingLogger();
    registry = new McpConnectionRegistry(logger, {
      idleTtlMs: TTL,
      sweepIntervalMs: SWEEP,
    });
    const close = vi.fn().mockResolvedValue(undefined);
    await registry.acquire("s1", () => Promise.resolve(fakeEntry("s1", close)));
    expect(registry.get("s1")).toBeDefined();

    await vi.advanceTimersByTimeAsync(TTL + SWEEP);

    expect(registry.get("s1")).toBeUndefined();
    expect(close).toHaveBeenCalledTimes(1);
    const terminate = rows.find((r) => r.eventType === AuditEventType.MCP_TERMINATE);
    expect(terminate?.secretId).toBe("s1");
    expect(terminate?.detail).toMatchObject({
      reason: "idle",
      server: "idle-mcp",
    });
    expect(terminate?.principalId).toBeUndefined();
  });

  it("a reuse hit re-stamps the entry, so a child in use is never swept", async () => {
    registry = new McpConnectionRegistry(null, {
      idleTtlMs: TTL,
      sweepIntervalMs: SWEEP,
    });
    const close = vi.fn().mockResolvedValue(undefined);
    await registry.acquire("s1", () => Promise.resolve(fakeEntry("s1", close)));

    await vi.advanceTimersByTimeAsync(TTL - SWEEP);
    await registry.acquire("s1", () => Promise.reject(new Error("must reuse, not reconnect")));
    await vi.advanceTimersByTimeAsync(TTL - SWEEP);
    expect(registry.get("s1")).toBeDefined();
    expect(close).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2 * SWEEP);
    expect(registry.get("s1")).toBeUndefined();
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("the sweep runs only while something is live — none before the first publish, none after the last teardown", async () => {
    registry = new McpConnectionRegistry(null, {
      idleTtlMs: TTL,
      sweepIntervalMs: SWEEP,
    });
    expect(vi.getTimerCount()).toBe(0);

    await registry.acquire("s1", () =>
      Promise.resolve(fakeEntry("s1", vi.fn().mockResolvedValue(undefined))),
    );
    expect(vi.getTimerCount()).toBe(1);
    await registry.terminate("s1", "test_cleanup");
    expect(vi.getTimerCount()).toBe(0);

    await registry.acquire("s2", () =>
      Promise.resolve(fakeEntry("s2", vi.fn().mockResolvedValue(undefined))),
    );
    expect(vi.getTimerCount()).toBe(1);
    registry.killAllSync();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("an entry still connecting is never swept", async () => {
    registry = new McpConnectionRegistry(null, {
      idleTtlMs: TTL,
      sweepIntervalMs: SWEEP,
    });
    await registry.acquire("ready", () =>
      Promise.resolve(fakeEntry("ready", vi.fn().mockResolvedValue(undefined))),
    );
    let publish: (entry: McpConnectionEntry) => void = () => undefined;
    const pending = registry.acquire(
      "slow",
      () => new Promise<McpConnectionEntry>((resolve) => (publish = resolve)),
    );
    await vi.advanceTimersByTimeAsync(TTL + SWEEP);
    expect(registry.get("ready")).toBeUndefined();

    publish(fakeEntry("slow", vi.fn().mockResolvedValue(undefined)));
    const entry = await pending;
    expect(entry.state).toBe("ready");
    expect(registry.get("slow")).toBe(entry);
  });
});
