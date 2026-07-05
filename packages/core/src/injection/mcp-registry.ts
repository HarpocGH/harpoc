import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { AuditEventType, MCP_SHUTDOWN_TIMEOUT_MS } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { InjectionGuard } from "./injection-guard.js";
import type { StdioChildTransport } from "./mcp-stdio-transport.js";

/** Max bytes of pattern-sanitized downstream stderr recorded in a crash audit entry. */
const CRASH_STDERR_TAIL_BYTES = 2_048;

export type McpEntryState = "connecting" | "ready" | "closing";

/**
 * One live downstream MCP server connection. Holds only credential/config
 * SHA-256 fingerprints — never plaintext.
 */
export interface McpConnectionEntry {
  secretId: string;
  serverName: string;
  transportKind: "stdio" | "http";
  client: Client;
  /** Set for stdio entries — the vault-spawned child transport. */
  stdioTransport?: StdioChildTransport;
  state: McpEntryState;
  /** Set when the connection closed without a deliberate terminate. */
  crashed: boolean;
  credentialFingerprint: string;
  configFingerprint: string;
  spawnedAt: number;
}

/**
 * In-memory lifecycle table for downstream MCP servers (thesis §4.5.4):
 * spawn on first use, reuse across calls, terminate on session end. On
 * unexpected exit the entry is removed and the crash audit-logged; respawn
 * happens only on the NEXT invocation — never automatically.
 */
export class McpConnectionRegistry {
  /** Coalesces concurrent first-use connects per secret. */
  private readonly connections = new Map<string, Promise<McpConnectionEntry>>();
  /** Ready entries, synchronously accessible for staleness checks and seal paths. */
  private readonly live = new Map<string, McpConnectionEntry>();

  constructor(private readonly auditLogger: AuditLogger | null) {}

  /** The ready entry for a secret, if one exists (undefined while connecting). */
  get(secretId: string): McpConnectionEntry | undefined {
    return this.live.get(secretId);
  }

  /**
   * Return the live connection for a secret, or establish one via `factory`.
   * Concurrent callers coalesce onto the same connect; a failed connect is
   * removed so the next invocation retries fresh.
   */
  async acquire(
    secretId: string,
    factory: () => Promise<McpConnectionEntry>,
  ): Promise<McpConnectionEntry> {
    const existing = this.connections.get(secretId);
    if (existing) return existing;

    const promise = this.connect(secretId, factory);
    this.connections.set(secretId, promise);
    try {
      return await promise;
    } catch (err) {
      this.connections.delete(secretId);
      throw err;
    }
  }

  /** Deliberately terminate one connection (rotation, config change). */
  async terminate(secretId: string, reason: string): Promise<void> {
    const promise = this.connections.get(secretId);
    if (!promise) return;
    this.connections.delete(secretId);

    let entry: McpConnectionEntry;
    try {
      entry = await promise;
    } catch {
      return;
    }
    await this.terminateEntry(entry, reason);
  }

  /** Graceful session-end teardown (lock/destroy): close all within a budget. */
  async closeAll(reason = "session_end"): Promise<void> {
    const entries = [...this.live.values()];
    this.connections.clear();

    if (entries.length === 0) return;

    let budgetTimer: NodeJS.Timeout | undefined;
    const budget = new Promise<void>((resolve) => {
      budgetTimer = setTimeout(resolve, MCP_SHUTDOWN_TIMEOUT_MS);
      if (budgetTimer.unref) budgetTimer.unref();
    });

    await Promise.race([
      Promise.allSettled(entries.map((entry) => this.terminateEntry(entry, reason))),
      budget,
    ]);
    if (budgetTimer) clearTimeout(budgetTimer);

    // Anything still alive after the budget is hard-killed.
    for (const entry of entries) {
      entry.stdioTransport?.killSync();
    }
    this.live.clear();
  }

  /**
   * Best-effort synchronous teardown for seal paths that cannot await
   * (wipeKeys covers lock, destroy and the session-monitor expiry seal).
   */
  killAllSync(): void {
    for (const entry of this.live.values()) {
      entry.state = "closing";
      entry.stdioTransport?.killSync();
      void entry.client.close().catch(() => undefined);
    }
    this.live.clear();
    this.connections.clear();
  }

  private async connect(
    secretId: string,
    factory: () => Promise<McpConnectionEntry>,
  ): Promise<McpConnectionEntry> {
    const entry = await factory();
    entry.state = "ready";
    this.live.set(secretId, entry);

    // Protocol assigns transport.onclose internally; the client-level hook is
    // the supported observation point for both crash and deliberate close.
    entry.client.onclose = () => this.handleClose(secretId, entry);

    return entry;
  }

  private handleClose(secretId: string, entry: McpConnectionEntry): void {
    if (this.live.get(secretId) === entry) {
      this.live.delete(secretId);
    }
    this.connections.delete(secretId);

    if (entry.state === "closing") return;

    // Unexpected exit: mark crashed (read by in-flight call error mapping),
    // audit with exit forensics. No respawn here — next invocation reconnects.
    entry.crashed = true;
    const exit = entry.stdioTransport?.exitInfo ?? null;
    this.auditLogger?.log({
      eventType: AuditEventType.MCP_CRASH,
      secretId,
      detail: {
        server: entry.serverName,
        transport: entry.transportKind,
        exit_code: exit?.code ?? null,
        signal: exit?.signal ?? null,
        uptime_ms: Date.now() - entry.spawnedAt,
        stderr_tail: this.sanitizedStderrTail(entry),
      },
      success: false,
    });
  }

  private async terminateEntry(entry: McpConnectionEntry, reason: string): Promise<void> {
    if (entry.state === "closing") return;
    entry.state = "closing";

    if (this.live.get(entry.secretId) === entry) {
      this.live.delete(entry.secretId);
    }

    this.auditLogger?.log({
      eventType: AuditEventType.MCP_TERMINATE,
      secretId: entry.secretId,
      detail: {
        server: entry.serverName,
        transport: entry.transportKind,
        reason,
        uptime_ms: Date.now() - entry.spawnedAt,
      },
      success: true,
    });

    try {
      await entry.client.close();
    } catch {
      entry.stdioTransport?.killSync();
    }
  }

  /**
   * Downstream stderr may contain the credential (a server can log its own
   * env). Exact-value redaction is impossible at crash time without retaining
   * plaintext, so the tail recorded in the audit detail is pattern-sanitized
   * and capped — and never reaches the agent-visible error.
   */
  private sanitizedStderrTail(entry: McpConnectionEntry): string | undefined {
    const raw = entry.stdioTransport?.stderrTail.toString();
    if (!raw) return undefined;
    const guard = new InjectionGuard();
    return guard.sanitize(raw.slice(-CRASH_STDERR_TAIL_BYTES));
  }
}
