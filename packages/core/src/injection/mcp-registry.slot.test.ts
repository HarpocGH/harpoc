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

// A stdio child as the registry reads it: the exit record (assigned by the
// transport before its close hook fires), a kill, an empty stderr ring.
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

// The slot (`connections`) has four removers. `terminate` reads and deletes
// synchronously, `closeAll` / `killAllSync` clear it under a generation bump,
// and `handleClose` is state-guarded (C1, 2026-09-10). `acquire`'s catch was
// the one remover that deleted by key alone.
describe("McpConnectionRegistry — a failed connect frees only its own slot (2026-09-11)", () => {
  it("a connect that fails after a terminate seated its successor leaves the successor alone", async () => {
    const registry = new McpConnectionRegistry(null);
    let rejectFirst: (err: Error) => void = () => undefined;
    const first = registry.acquire(
      "s1",
      () => new Promise<McpConnectionEntry>((_, reject) => (rejectFirst = reject)),
    );
    // Frees the slot synchronously, then awaits the in-flight connect — a
    // revoke, a lazy expiry, a delete or a config update landing mid-connect.
    const terminated = registry.terminate("s1", "credential_rotated");
    const closeSecond = vi.fn().mockResolvedValue(undefined);
    const second = await registry.acquire("s1", () =>
      Promise.resolve(fakeEntry("s1", closeSecond)),
    );
    expect(registry.get("s1")).toBe(second);

    rejectFirst(new Error("initialize timed out"));
    await expect(first).rejects.toThrow("initialize timed out");
    await terminated;

    // The successor is still the seated connect: a third acquire reuses it
    // and calls no factory.
    const third = await registry.acquire("s1", () =>
      Promise.reject(new Error("must reuse, not reconnect")),
    );
    expect(third).toBe(second);
    expect(registry.get("s1")).toBe(second);
    expect(closeSecond).not.toHaveBeenCalled();

    await registry.closeAll("test_cleanup");
    expect(closeSecond).toHaveBeenCalledTimes(1);
  });

  it("control: a failed connect with no successor frees its slot, and the next acquire connects fresh", async () => {
    const registry = new McpConnectionRegistry(null);
    await expect(
      registry.acquire("s1", () => Promise.reject(new Error("spawn failed"))),
    ).rejects.toThrow("spawn failed");
    expect(registry.get("s1")).toBeUndefined();

    const factory = vi.fn(() =>
      Promise.resolve(fakeEntry("s1", vi.fn().mockResolvedValue(undefined))),
    );
    const entry = await registry.acquire("s1", factory);
    expect(factory).toHaveBeenCalledTimes(1);
    expect(registry.get("s1")).toBe(entry);

    await registry.closeAll("test_cleanup");
  });
});

// The success-path sibling (2026-09-12): `connect` publishes only while the
// slot holds no OTHER connect for the secret. An empty slot still publishes —
// the terminate that freed it awaits this connect and closes it with its row.
describe("McpConnectionRegistry — a connect publishes only while its slot is its own (2026-09-12)", () => {
  it("a connect that resolves after a terminate seated its successor is torn down, never published", async () => {
    const { logger, rows } = recordingLogger();
    const registry = new McpConnectionRegistry(logger);
    let resolveFirst: (entry: McpConnectionEntry) => void = () => undefined;
    const first = registry.acquire(
      "s1",
      () => new Promise<McpConnectionEntry>((resolve) => (resolveFirst = resolve)),
    );
    // Frees the slot synchronously, then awaits the in-flight connect.
    const terminated = registry.terminate("s1", "secret_revoked");
    const closeSecond = vi.fn().mockResolvedValue(undefined);
    const second = await registry.acquire("s1", () =>
      Promise.resolve(fakeEntry("s1", closeSecond)),
    );
    expect(registry.get("s1")).toBe(second);

    const closeFirst = vi.fn().mockResolvedValue(undefined);
    const killFirst = vi.fn();
    const late = { ...fakeEntry("s1", closeFirst), stdioTransport: fakeStdio(null, killFirst) };
    resolveFirst(late);
    await expect(first).rejects.toThrow("superseded while connecting");
    await terminated;
    // No row for the superseded window: the pending terminate's await
    // rejected before it held an entry, and the late child was torn down
    // without the crash path.
    expect(rows).toEqual([]);

    // The late child is dead; the successor is untouched and still the seated connect.
    expect(late.state).toBe("closing");
    expect(killFirst).toHaveBeenCalledTimes(1);
    expect(closeFirst).toHaveBeenCalledTimes(1);
    expect(registry.get("s1")).toBe(second);
    const third = await registry.acquire("s1", () =>
      Promise.reject(new Error("must reuse, not reconnect")),
    );
    expect(third).toBe(second);
    expect(closeSecond).not.toHaveBeenCalled();

    await registry.closeAll("test_cleanup");
    expect(closeSecond).toHaveBeenCalledTimes(1);
    expect(rows.map((row) => row.eventType)).toEqual([AuditEventType.MCP_TERMINATE]);
  });

  it("control: a connect that resolves into the empty slot a terminate freed publishes, and the pending terminate closes it with its row", async () => {
    const { logger, rows } = recordingLogger();
    const registry = new McpConnectionRegistry(logger);
    let resolveFirst: (entry: McpConnectionEntry) => void = () => undefined;
    const first = registry.acquire(
      "s1",
      () => new Promise<McpConnectionEntry>((resolve) => (resolveFirst = resolve)),
    );
    const terminated = registry.terminate("s1", "secret_revoked");
    const closeFirst = vi.fn().mockResolvedValue(undefined);
    resolveFirst(fakeEntry("s1", closeFirst));
    const entry = await first;
    await terminated;

    expect(entry.state).toBe("closing");
    expect(closeFirst).toHaveBeenCalledTimes(1);
    expect(registry.get("s1")).toBeUndefined();
    expect(rows.map((row) => row.eventType)).toEqual([AuditEventType.MCP_TERMINATE]);
    expect(rows[0]?.detail).toMatchObject({ server: "slot-mcp", reason: "secret_revoked" });
  });

  it("a connect that resolves after a seal cleared the map and a post-seal acquire seated a successor leaves the successor alone (the catch's second beneficiary)", async () => {
    const registry = new McpConnectionRegistry(null);
    let resolveFirst: (entry: McpConnectionEntry) => void = () => undefined;
    const first = registry.acquire(
      "s1",
      () => new Promise<McpConnectionEntry>((resolve) => (resolveFirst = resolve)),
    );
    registry.killAllSync();
    const closeSecond = vi.fn().mockResolvedValue(undefined);
    const second = await registry.acquire("s1", () =>
      Promise.resolve(fakeEntry("s1", closeSecond)),
    );
    const closeFirst = vi.fn().mockResolvedValue(undefined);
    resolveFirst(fakeEntry("s1", closeFirst));
    await expect(first).rejects.toThrow("vault session ended while connecting");

    expect(closeFirst).toHaveBeenCalledTimes(1);
    expect(registry.get("s1")).toBe(second);
    const third = await registry.acquire("s1", () =>
      Promise.reject(new Error("must reuse, not reconnect")),
    );
    expect(third).toBe(second);
    expect(closeSecond).not.toHaveBeenCalled();

    await registry.closeAll("test_cleanup");
    expect(closeSecond).toHaveBeenCalledTimes(1);
  });
});

// The transport assigns `exitInfo` before its close hook fires, and the SDK
// runs the client hook nobody had installed yet: a child that exits between
// the handshake and the publish leaves an exit record and a dead client.
describe("McpConnectionRegistry — a child already dead at publish takes the crash path (2026-09-12)", () => {
  it("the connect rejects MCP_SERVER_CRASHED with the forensics, one mcp.crash row is written, nothing is published, and the next acquire connects fresh", async () => {
    const { logger, rows } = recordingLogger();
    const registry = new McpConnectionRegistry(logger);
    const closeDead = vi.fn().mockResolvedValue(undefined);
    const dead = {
      ...fakeEntry("s1", closeDead),
      stdioTransport: fakeStdio({ code: 1, signal: null }),
    };
    const err = await expectVaultError(
      () => registry.acquire("s1", () => Promise.resolve(dead)),
      ErrorCode.MCP_SERVER_CRASHED,
    );
    expect(err.details).toEqual({ server: "slot-mcp", exit_code: 1, signal: null });
    expect(dead.crashed).toBe(true);
    expect(registry.get("s1")).toBeUndefined();
    expect(rows.map((row) => row.eventType)).toEqual([AuditEventType.MCP_CRASH]);
    expect(rows[0]).toMatchObject({
      secretId: "s1",
      success: false,
      detail: { server: "slot-mcp", transport: "stdio", exit_code: 1, signal: null },
    });

    const factory = vi.fn(() =>
      Promise.resolve(fakeEntry("s1", vi.fn().mockResolvedValue(undefined))),
    );
    const fresh = await registry.acquire("s1", factory);
    expect(factory).toHaveBeenCalledTimes(1);
    expect(registry.get("s1")).toBe(fresh);

    await registry.closeAll("test_cleanup");
  });
});

// The seal path's per-entry teardown, pinned on fake entries: `killAllSync`
// cannot await, so each live entry is marked closing, its child killed, its
// client's close swallowed and its resources disposed — once each — and both
// tables are empty afterwards. The same idiom `connect`'s generation and
// superseded branches take (`killEntrySync`, 2026-09-14).
describe("McpConnectionRegistry — killAllSync tears every live entry down synchronously (2026-09-14)", () => {
  function expectTornDown(
    entry: McpConnectionEntry,
    kill: () => void,
    close: () => Promise<void>,
    dispose: () => void,
  ): void {
    expect(entry.state).toBe("closing");
    expect(kill).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(dispose).toHaveBeenCalledTimes(1);
  }

  it("each live entry is closing, killed once, closed once and disposed once — a rejecting close swallowed — both maps are empty, no row, and the next acquire connects fresh", async () => {
    const { logger, rows } = recordingLogger();
    const registry = new McpConnectionRegistry(logger);
    const closeA = vi.fn().mockResolvedValue(undefined);
    const killA = vi.fn();
    const disposeA = vi.fn();
    const a = {
      ...fakeEntry("s1", closeA),
      stdioTransport: fakeStdio(null, killA),
      dispose: disposeA,
    };
    const closeB = vi.fn().mockRejectedValue(new Error("already gone"));
    const killB = vi.fn();
    const disposeB = vi.fn();
    const b = {
      ...fakeEntry("s2", closeB),
      stdioTransport: fakeStdio(null, killB),
      dispose: disposeB,
    };
    expect(await registry.acquire("s1", () => Promise.resolve(a))).toBe(a);
    expect(await registry.acquire("s2", () => Promise.resolve(b))).toBe(b);

    registry.killAllSync();

    expectTornDown(a, killA, closeA, disposeA);
    expectTornDown(b, killB, closeB, disposeB);
    expect(registry.get("s1")).toBeUndefined();
    expect(registry.get("s2")).toBeUndefined();
    expect(rows).toEqual([]);

    const factory = vi.fn(() =>
      Promise.resolve(fakeEntry("s1", vi.fn().mockResolvedValue(undefined))),
    );
    const fresh = await registry.acquire("s1", factory);
    expect(factory).toHaveBeenCalledTimes(1);
    expect(registry.get("s1")).toBe(fresh);

    await registry.closeAll("test_cleanup");
  });
});
