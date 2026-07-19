import { readFileSync, writeFileSync } from "node:fs";
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { VaultEngine, SessionManager } from "@harpoc/core";
import { createMcpServer } from "@harpoc/mcp-server";
import { createApp } from "@harpoc/rest-api";
import { DirectClient } from "@harpoc/sdk";
import { SESSION_CLEANUP_INTERVAL_MS, VaultState } from "@harpoc/shared";
import type { SessionFile } from "@harpoc/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool } from "./helpers/mcp-helpers.js";

const PASSWORD = "session-expiry-pw";

function tamperSessionExpiry(sessionPath: string, expiresInMs: number): void {
  const raw = readFileSync(sessionPath, "utf8");
  const session = JSON.parse(raw) as SessionFile;
  session.expires_at = Date.now() + expiresInMs;
  writeFileSync(sessionPath, JSON.stringify(session, null, 2), "utf8");
}

describe("Session Expiry", () => {
  let vault: TestVault;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault(PASSWORD);
    await vault.engine.destroy();
  });

  afterAll(async () => {
    destroyTestVault(vault).catch(() => {});
  });

  // ---- Test 1: Session monitor detects expired session --------------------
  // Also covers MCP, REST, SDK behavior after monitor-induced seal. Real
  // machinery end to end: the session file carries a real past expires_at and
  // the monitor's real file read notices it. The interval is fired with fake
  // timers; the tick's file I/O resolves on the real event loop, so the
  // timers go back to real before polling for the sealed state.
  it("session monitor detects expired session — MCP/REST/SDK all fail", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    const token = engine1.createToken("test-agent", ["admin"]);
    await engine1.destroy();

    vi.useFakeTimers();
    const engine2 = new VaultEngine({
      dbPath: vault.dbPath,
      sessionPath: vault.sessionPath,
    });
    try {
      const loaded = await engine2.loadSession();
      expect(loaded).toBe(true);
      expect(engine2.getState()).toBe(VaultState.UNLOCKED);

      // Set up MCP, REST, SDK before expiry
      const mcpServer: McpServer = createMcpServer({ engine: engine2, allowTokenless: true });
      const app = createApp(engine2);
      const client = new DirectClient(engine2);

      // The stored session expires mid-flight (real file, real past timestamp)
      tamperSessionExpiry(vault.sessionPath, -1);

      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS + 1_000);
      vi.useRealTimers();
      await vi.waitFor(() => {
        expect(engine2.getState()).toBe(VaultState.SEALED);
      });

      // MCP tool should error
      const mcpResult = await callTool(mcpServer, "list_secrets", {});
      expect(mcpResult.isError).toBe(true);

      // REST should return 503
      const res = await app.request("/api/v1/secrets", {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(res.status).toBe(503);

      // SDK DirectClient should throw VAULT_LOCKED
      await expect(client.listSecrets()).rejects.toThrow("Vault is locked");

      await engine2.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- Test 2: MCP fails when session expired before load -----------------
  it("MCP tool calls fail when session is already expired", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.destroy();
    tamperSessionExpiry(vault.sessionPath, -1); // already expired

    const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(false);
    expect(engine2.getState()).toBe(VaultState.SEALED);

    const mcpServer: McpServer = createMcpServer({ engine: engine2, allowTokenless: true });
    const result = await callTool(mcpServer, "list_secrets", {});
    expect(result.isError).toBe(true);
    await engine2.destroy();
  });

  // ---- Test 3: REST returns 503 when session expired before load ----------
  it("REST API returns 503 when session is already expired", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    const token = engine1.createToken("test-agent", ["admin"]);
    await engine1.destroy();
    tamperSessionExpiry(vault.sessionPath, -1);

    const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine2.loadSession(); // returns false
    const app = createApp(engine2);

    const res = await app.request("/api/v1/secrets", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(503);
    await engine2.destroy();
  });

  // ---- Test 4: SDK DirectClient throws when session expired ---------------
  it("SDK DirectClient throws VAULT_LOCKED when session expired", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.destroy();
    tamperSessionExpiry(vault.sessionPath, -1);

    const engine2 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine2.loadSession(); // returns false
    const client = new DirectClient(engine2);

    await expect(client.listSecrets()).rejects.toThrow("Vault is locked");
    await engine2.destroy();
  });

  // ---- Test 5: Long TTL session does NOT expire prematurely ---------------
  it("session with long TTL does NOT expire prematurely", async () => {
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

      // Advance by one monitor interval — 15min session should still be valid
      await vi.advanceTimersByTimeAsync(SESSION_CLEANUP_INTERVAL_MS + 1_000);

      expect(engine2.getState()).toBe(VaultState.UNLOCKED);
      const secrets = engine2.listSecrets();
      expect(secrets).toBeDefined();
      await engine2.destroy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- Test 6: readSession returns null for expired session ---------------
  it("readSession returns null for expired session file", async () => {
    const engine1 = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine1.unlock(PASSWORD);
    await engine1.destroy();
    tamperSessionExpiry(vault.sessionPath, -1);

    const sessionManager = new SessionManager(vault.sessionPath);
    const session = await sessionManager.readSession();
    expect(session).toBeNull();
  });

  // ---- Test 7: Re-unlock after expiry works normally ----------------------
  it("re-unlock after expiry creates fresh session and works normally", async () => {
    // Previous test left session expired
    const engine = new VaultEngine({ dbPath: vault.dbPath, sessionPath: vault.sessionPath });
    await engine.unlock(PASSWORD);
    expect(engine.getState()).toBe(VaultState.UNLOCKED);

    const secrets = engine.listSecrets();
    expect(secrets).toBeDefined();

    const sessionManager = new SessionManager(vault.sessionPath);
    const session = await sessionManager.readSession();
    expect(session).not.toBeNull();

    await engine.destroy();
  });
});
