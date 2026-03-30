import type { VaultEngine } from "@harpoc/core";

const DEFAULT_CHECK_INTERVAL_MS = 60_000; // 60 seconds
const EXPIRING_WITHIN_MS = 5 * 60 * 1000; // 5 minutes
const MAX_RETRIES = 3;
const DEFAULT_INITIAL_RETRY_DELAY_MS = 1_000;

export interface TokenRefreshSchedulerOptions {
  checkIntervalMs?: number;
  initialRetryDelayMs?: number;
}

export class TokenRefreshScheduler {
  private engine: VaultEngine;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private checkIntervalMs: number;
  private initialRetryDelayMs: number;

  constructor(engine: VaultEngine, options?: TokenRefreshSchedulerOptions) {
    this.engine = engine;
    this.checkIntervalMs = options?.checkIntervalMs ?? DEFAULT_CHECK_INTERVAL_MS;
    this.initialRetryDelayMs = options?.initialRetryDelayMs ?? DEFAULT_INITIAL_RETRY_DELAY_MS;
  }

  /**
   * Start the background refresh scheduler.
   * Periodically checks for expiring OAuth tokens and refreshes them.
   */
  start(): void {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      this.tick().catch(() => {
        // Errors are handled per-token in tick()
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
   * Force an immediate refresh of a specific token.
   */
  async refreshNow(secretId: string): Promise<number | null> {
    return this.refreshWithRetry(secretId);
  }

  /**
   * Run one tick: find expiring tokens and refresh them.
   */
  async tick(): Promise<void> {
    const expiringTokens = this.engine.getExpiringOAuthTokens(EXPIRING_WITHIN_MS);

    for (const token of expiringTokens) {
      try {
        await this.refreshWithRetry(token.secret_id);
      } catch {
        // Individual token refresh failure is logged by VaultEngine.
        // We continue to process remaining tokens.
      }
    }
  }

  private async refreshWithRetry(secretId: string): Promise<number | null> {
    let lastError: unknown;
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        return await this.engine.refreshOAuthToken(secretId);
      } catch (err) {
        lastError = err;
        if (attempt < MAX_RETRIES - 1) {
          const delay = this.initialRetryDelayMs * Math.pow(4, attempt);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }
    throw lastError;
  }

  get isRunning(): boolean {
    return this.intervalId !== null;
  }
}
