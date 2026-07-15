import type { VaultEngine } from "@harpoc/core";

const DEFAULT_CHECK_INTERVAL_MS = 60_000; // 60 seconds
const EXPIRING_WITHIN_MS = 5 * 60 * 1000; // 5 minutes
const MAX_RETRIES = 3;
const DEFAULT_INITIAL_RETRY_DELAY_MS = 1_000;
const MAX_QUARANTINE_MS = 60 * 60 * 1000; // 1 hour backoff cap

interface QuarantineEntry {
  failures: number;
  nextAttemptAt: number;
}

export interface TokenRefreshSchedulerOptions {
  checkIntervalMs?: number;
  initialRetryDelayMs?: number;
  /**
   * Called when a scheduled per-token refresh fails after all retries (once
   * per quarantine escalation, not per skipped tick). Default: no-op — the
   * package stays console-free; the host decides how to report. `refreshNow`
   * rethrows to its caller instead.
   */
  onRefreshError?: (secretId: string, err: unknown) => void;
}

export class TokenRefreshScheduler {
  private engine: VaultEngine;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private checkIntervalMs: number;
  private initialRetryDelayMs: number;
  private onRefreshError?: (secretId: string, err: unknown) => void;
  private tickInProgress = false;
  /**
   * Per-secret failure quarantine: a broken token (revoked grant, offline
   * provider) is re-discovered by every tick's expiring query forever — the
   * backoff lives here, in memory (a restart retries immediately; acceptable).
   */
  private readonly quarantine = new Map<string, QuarantineEntry>();

  constructor(engine: VaultEngine, options?: TokenRefreshSchedulerOptions) {
    this.engine = engine;
    this.checkIntervalMs = options?.checkIntervalMs ?? DEFAULT_CHECK_INTERVAL_MS;
    this.initialRetryDelayMs = options?.initialRetryDelayMs ?? DEFAULT_INITIAL_RETRY_DELAY_MS;
    this.onRefreshError = options?.onRefreshError;
  }

  /**
   * Start the background refresh scheduler.
   * Periodically checks for expiring OAuth tokens and refreshes them.
   *
   * A tick that outlives the interval (slow provider, many retrying tokens)
   * must not overlap the next one: overlapping ticks POST the same
   * refresh_token twice, which rotation-detecting providers punish by
   * revoking the token family. Overlapped firings are skipped — the next
   * tick re-discovers still-expiring tokens.
   */
  start(): void {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      if (this.tickInProgress) return;
      this.tickInProgress = true;
      this.tick()
        .catch(() => {
          // Errors are handled per-token in tick()
        })
        .finally(() => {
          this.tickInProgress = false;
        });
    }, this.checkIntervalMs);
  }

  /**
   * Stop the background refresh scheduler.
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /**
   * Force an immediate refresh of a specific token. Bypasses the failure
   * quarantine (an explicit operator action), but updates it on the outcome.
   */
  async refreshNow(secretId: string): Promise<number | null> {
    return this.refreshWithRetry(secretId);
  }

  /**
   * Run one tick: find expiring tokens and refresh them. Tokens inside their
   * quarantine window are skipped — without the backoff, a permanently broken
   * token is retried every tick, forever.
   */
  async tick(): Promise<void> {
    const expiringTokens = this.engine.getExpiringOAuthTokens(EXPIRING_WITHIN_MS);
    const now = Date.now();

    for (const token of expiringTokens) {
      const entry = this.quarantine.get(token.secret_id);
      if (entry && now < entry.nextAttemptAt) continue;
      try {
        await this.refreshWithRetry(token.secret_id);
      } catch (err) {
        // One broken token must not halt the loop; the host is notified,
        // remaining tokens are still processed.
        this.onRefreshError?.(token.secret_id, err);
      }
    }
  }

  private async refreshWithRetry(secretId: string): Promise<number | null> {
    let lastError: unknown;
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const result = await this.engine.refreshOAuthToken(secretId);
        this.quarantine.delete(secretId);
        return result;
      } catch (err) {
        lastError = err;
        if (attempt < MAX_RETRIES - 1) {
          const delay = this.initialRetryDelayMs * Math.pow(4, attempt);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }
    this.recordFailure(secretId);
    throw lastError;
  }

  /** Exponential backoff on the check interval, capped at one hour. */
  private recordFailure(secretId: string): void {
    const failures = (this.quarantine.get(secretId)?.failures ?? 0) + 1;
    const backoffMs = Math.min(this.checkIntervalMs * Math.pow(2, failures), MAX_QUARANTINE_MS);
    this.quarantine.set(secretId, { failures, nextAttemptAt: Date.now() + backoffMs });
  }

  get isRunning(): boolean {
    return this.intervalId !== null;
  }
}
