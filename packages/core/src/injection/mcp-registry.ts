import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { AuditEventType, MCP_SHUTDOWN_TIMEOUT_MS, VaultError } from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import { withAttribution } from "../audit/attribution.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { InjectionGuard } from "./injection-guard.js";
import type { StdioChildTransport } from "./mcp-stdio-transport.js";
import { redactSecretEncodings } from "./output-sanitizer.js";

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
  /**
   * Optional transport-resource teardown (the HTTP entries' pinned dispatcher).
   * Idempotent; called on every teardown path — terminate, crash, seal.
   */
  dispose?: () => void;
  state: McpEntryState;
  /**
   * The plaintext credential injected into this connection, kept so the crash
   * path can redact it out of the downstream stderr tail it records. Held for
   * exactly as long as the child that already has it in its environment.
   */
  redact?: string;
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
  /**
   * Bumped whenever the registry is cleared wholesale (session end, seal). A
   * connect that started before the clear must not publish into the registry
   * afterwards: the seal has already walked the table, so that entry — a child
   * holding the plaintext credential — would outlive the keys that authorized
   * it with no teardown path left.
   */
  private generation = 0;

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

  /**
   * Deliberately terminate one connection (rotation, config change). The
   * optional attribution names the principal whose call drove the teardown —
   * a vault-initiated terminate (session end, lazy expiry) passes none and
   * keeps the NULL-principal shape.
   */
  async terminate(secretId: string, reason: string, attribution?: AuditAttribution): Promise<void> {
    const promise = this.connections.get(secretId);
    if (!promise) return;
    this.connections.delete(secretId);

    let entry: McpConnectionEntry;
    try {
      entry = await promise;
    } catch {
      return;
    }
    await this.terminateEntry(entry, reason, attribution);
  }

  /** Graceful session-end teardown (lock/destroy): close all within a budget. */
  async closeAll(reason = "session_end"): Promise<void> {
    this.generation++;
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
    this.generation++;
    for (const entry of this.live.values()) {
      entry.state = "closing";
      entry.stdioTransport?.killSync();
      void entry.client.close().catch(() => undefined);
      entry.dispose?.();
    }
    this.live.clear();
    this.connections.clear();
  }

  private async connect(
    secretId: string,
    factory: () => Promise<McpConnectionEntry>,
  ): Promise<McpConnectionEntry> {
    const generation = this.generation;
    const entry = await factory();
    if (this.generation !== generation) {
      // The vault sealed (or the session ended) while this connect was in
      // flight. Tear the child down here — the same hard teardown the seal path
      // performs — instead of publishing it into a registry nothing will walk
      // again.
      entry.state = "closing";
      entry.stdioTransport?.killSync();
      void entry.client.close().catch(() => undefined);
      entry.dispose?.();
      throw VaultError.mcpConnectFailed(entry.serverName, "vault session ended while connecting");
    }
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
    entry.dispose?.();

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

  private async terminateEntry(
    entry: McpConnectionEntry,
    reason: string,
    attribution?: AuditAttribution,
  ): Promise<void> {
    if (entry.state === "closing") return;
    entry.state = "closing";

    if (this.live.get(entry.secretId) === entry) {
      this.live.delete(entry.secretId);
    }

    this.auditLogger?.log(
      withAttribution(
        {
          eventType: AuditEventType.MCP_TERMINATE,
          secretId: entry.secretId,
          detail: {
            server: entry.serverName,
            transport: entry.transportKind,
            reason,
            uptime_ms: Date.now() - entry.spawnedAt,
          },
          success: true,
        },
        attribution,
      ),
    );

    try {
      await entry.client.close();
    } catch {
      entry.stdioTransport?.killSync();
    } finally {
      entry.dispose?.();
    }
  }

  /**
   * Downstream stderr may contain the credential — a server logging its own
   * environment is a common debug accident, and the audit detail is durable
   * and served to admin-scoped MCP clients, which otherwise have no path to
   * any secret value. Pattern sanitization alone does not recognize an
   * arbitrary credential, so the tail is first passed through exact-value
   * redaction against the value that was injected into this very child
   * (`redact`, supplied by the injector that holds it), exactly as the result
   * path does; the pattern pass and the cap then still apply.
   */
  private sanitizedStderrTail(entry: McpConnectionEntry): string | undefined {
    const raw = entry.stdioTransport?.stderrTail.toString();
    if (!raw) return undefined;
    const tail = raw.slice(-CRASH_STDERR_TAIL_BYTES);
    const exact = entry.redact ? redactSecretEncodings(tail, entry.redact) : tail;
    const guard = new InjectionGuard();
    return guard.sanitize(exact);
  }
}
