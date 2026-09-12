import { describe, expect, it, vi } from "vitest";
import type { McpConnectionEntry } from "./mcp-registry.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

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
