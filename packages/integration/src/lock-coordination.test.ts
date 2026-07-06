import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { VaultEngine, SessionManager } from "@harpoc/core";
import { createMcpServer } from "@harpoc/mcp-server";
import { createApp } from "@harpoc/rest-api";
import { DirectClient } from "@harpoc/sdk";
import { SESSION_CLEANUP_INTERVAL_MS, VaultState } from "@harpoc/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool } from "./helpers/mcp-helpers.js";

const PASSWORD = "lock-coord-test-pw";

describe("Lock Coordination", () => {
  let vault: TestVault;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    await vault.engine.destroy();
  });

  afterAll(async () => {
    destroyTestVault(vault).catch(() => {});
  });

  // ---- Test 1: Engine2 detects Engine1's lock via monitor -----------------
  // Uses mocked readStoredSession (returns null after lock erases session) with fake timers,
  // same pattern as session-expiry test 1.
  it("Engine2 detects Engine1's lock within one monitor interval", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.destroy();

    vi.useFakeTimers();
    try {
      const engine2 = new VaultEngine({
        dbPath: vault.dbPath,
        sessionPath: vault.sessionPath,
      });
      await engine2.loadSession();
      expect(engine2.getState()).toBe(VaultState.UNLOCKED);

      // Simulate Engine1 locking (session file erased) by mocking readStoredSession to return null
      const spy = vi.spyOn(SessionManager.prototype, "readStoredSession").mockResolvedValue(null);

      // Advance past monitor interval
      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS + 1_000);

      expect(engine2.getState()).toBe(VaultState.SEALED);
      expect(spy).toHaveBeenCalled();

      spy.mockRestore();
      await engine2.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- Test 2: REST returns 503 after Engine1 locks -----------------------
  it("REST app on Engine2 returns 503 after Engine1 locks", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    const token = engine1.createToken("test-agent", ["admin"]);
    await engine1.destroy();

    vi.useFakeTimers();
    try {
      const engine2 = new VaultEngine({
        dbPath: vault.dbPath,
        sessionPath: vault.sessionPath,
      });
      await engine2.loadSession();
      const app = createApp(engine2);

      const spy = vi.spyOn(SessionManager.prototype, "readStoredSession").mockResolvedValue(null);
      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS + 1_000);

      const res = await app.request("/api/v1/secrets", {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(res.status).toBe(503);

      spy.mockRestore();
      await engine2.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- Test 3: MCP tool on Engine2 errors after Engine1 locks -------------
  it("MCP tool on Engine2 returns error after Engine1 locks", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.destroy();

    vi.useFakeTimers();
    try {
      const engine2 = new VaultEngine({
        dbPath: vault.dbPath,
        sessionPath: vault.sessionPath,
      });
      await engine2.loadSession();
      const mcpServer: McpServer = createMcpServer({ engine: engine2 });

      const spy = vi.spyOn(SessionManager.prototype, "readStoredSession").mockResolvedValue(null);
      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS + 1_000);

      const result = await callTool(mcpServer, "list_secrets", {});
      expect(result.isError).toBe(true);

      spy.mockRestore();
      await engine2.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- Test 4: SDK DirectClient fails after Engine1 locks -----------------
  it("SDK DirectClient fails with VAULT_LOCKED after Engine1 locks", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.destroy();

    vi.useFakeTimers();
    try {
      const engine2 = new VaultEngine({
        dbPath: vault.dbPath,
        sessionPath: vault.sessionPath,
      });
      await engine2.loadSession();
      const client = new DirectClient(engine2);

      const spy = vi.spyOn(SessionManager.prototype, "readStoredSession").mockResolvedValue(null);
      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS + 1_000);

      await expect(client.listSecrets()).rejects.toThrow("Vault is locked");

      spy.mockRestore();
      await engine2.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- Test 5: Seal happens within exactly one monitor interval -----------
  it("seal happens after one interval, not before", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.destroy();

    vi.useFakeTimers();
    try {
      const engine2 = new VaultEngine({
        dbPath: vault.dbPath,
        sessionPath: vault.sessionPath,
      });
      await engine2.loadSession();

      const spy = vi.spyOn(SessionManager.prototype, "readStoredSession").mockResolvedValue(null);

      // Advance halfway — monitor should NOT have fired yet
      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS / 2);
      expect(engine2.getState()).toBe(VaultState.UNLOCKED);

      // Advance past the interval — monitor fires and seals
      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS / 2 + 1_000);
      expect(engine2.getState()).toBe(VaultState.SEALED);

      spy.mockRestore();
      await engine2.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- Test 6: New Engine3 can re-unlock after lock -----------------------
  it("new engine can re-unlock and function normally after lock", async () => {
    // Engine1 unlocks then locks (erases session)
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.lock();

    // Engine3 re-unlocks
    const engine3 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine3.unlock(PASSWORD);
    expect(engine3.getState()).toBe(VaultState.UNLOCKED);

    const secrets = engine3.listSecrets();
    expect(secrets).toBeDefined();
    await engine3.destroy();
  });

  // ---- Test 7: Audit trail records the lock event -------------------------
  it("audit trail records the lock event from Engine1", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.lock();

    // Engine2 re-unlocks and checks audit
    const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine2.unlock(PASSWORD);

    const events = engine2.queryAudit();
    const types = events.map((e) => e.event_type);
    expect(types).toContain("vault.lock");

    await engine2.destroy();
  });
});
