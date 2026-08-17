import type { VaultEngine } from "@harpoc/core";

const DEFAULT_CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
const EXPIRING_QUERY_DAYS = 366;
const DAY_MS = 86_400_000;
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1_000;
const MAX_QUARANTINE_MS = 24 * 60 * 60 * 1000; // 24 hour backoff cap
const DEFAULT_STOP_DRAIN_TIMEOUT_MS = 10_000;

interface QuarantineEntry {
  failures: number;
  nextAttemptAt: number;
}

/**
 * The renewal half of the certificate manager, kept structural: the scheduler
 * drives renewals without depending on the manager that performs them. The
 * result is unconstrained — the manager returns the refreshed status, the
 * scheduler only cares that the promise settled.
 */
interface CertificateRenewer {
  renewCertificate(secretId: string): Promise<unknown>;
}

export interface RenewalSchedulerOptions {
  checkIntervalMs?: number;
  /**
   * Called when a scheduled per-certificate renewal fails after all retries
   * (once per quarantine escalation, not per skipped tick). Default: no-op —
   * the package stays console-free; the host decides how to report.
   * `renewNow` rethrows to its caller instead.
   */
  onRenewError?: (secretId: string, err: unknown) => void;
}

export class RenewalScheduler {
  private engine: Pick<VaultEngine, "getExpiringCertificates">;
  private renewer: CertificateRenewer;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private checkIntervalMs: number;
  private onRenewError?: (secretId: string, err: unknown) => void;
  private tickInProgress = false;
  private currentTick: Promise<void> | null = null;
  /**
   * Per-certificate failure quarantine: a certificate that cannot be renewed
   * (revoked ACME account, a challenge that will never validate) is
   * re-discovered by every tick's expiring query forever — the backoff lives
   * here, in memory (a restart retries immediately; acceptable).
   */
  private readonly quarantine = new Map<string, QuarantineEntry>();

  constructor(
    engine: Pick<VaultEngine, "getExpiringCertificates">,
    renewer: CertificateRenewer,
    options?: RenewalSchedulerOptions,
  ) {
    this.engine = engine;
    this.renewer = renewer;
    this.checkIntervalMs = options?.checkIntervalMs ?? DEFAULT_CHECK_INTERVAL_MS;
    this.onRenewError = options?.onRenewError;
  }

  /**
   * Start the background renewal scheduler.
   * Periodically checks for certificates inside their renewal window and
   * renews them.
   *
   * A tick that outlives the interval (slow CA, many retrying certificates)
   * must not overlap the next one: overlapping ticks place a second order for
   * the same names while the first is still in flight, which burns the CA's
   * duplicate-certificate rate limit and leaves an issued certificate the
   * vault never stored. Overlapped firings are skipped — the next tick
   * re-discovers still-due certificates.
   */
  start(): void {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      if (this.tickInProgress) return;
      this.tickInProgress = true;
      this.currentTick = this.tick()
        .catch(() => {
          // Errors are handled per-certificate in tick()
        })
        .finally(() => {
          this.tickInProgress = false;
          this.currentTick = null;
        });
    }, this.checkIntervalMs);
  }

  /**
   * Stop the background renewal scheduler, draining an in-flight tick.
   *
   * An order abandoned between issuance and storage is lost for good: the CA
   * counted the certificate against the rate limit, the vault holds neither
   * it nor its private key. The drain is bounded so a hung CA cannot block
   * shutdown; a response arriving after the bound is lost (accepted residual
   * — the caller chose to stop). Fire-and-forget callers may ignore the
   * returned promise.
   */
  async stop(drainTimeoutMs: number = DEFAULT_STOP_DRAIN_TIMEOUT_MS): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    const inFlight = this.currentTick;
    if (!inFlight) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const bound = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, drainTimeoutMs);
      if (timer.unref) timer.unref();
    });
    await Promise.race([inFlight, bound]);
    if (timer) clearTimeout(timer);
  }

  /**
   * Force an immediate renewal of a specific certificate. Bypasses the
   * failure quarantine (an explicit operator action), but updates it on the
   * outcome.
   */
  async renewNow(secretId: string): Promise<void> {
    return this.renewWithRetry(secretId);
  }

  /**
   * Run one tick: find due certificates and renew them.
   *
   * The store query takes a single global window, but the renewal threshold
   * is per row (`renew_before_days`), so the tick casts a wide net — a full
   * year — and applies each row's own window here. Certificates inside their
   * quarantine window are skipped: without the backoff, one that can never be
   * renewed is retried every tick, forever.
   */
  async tick(): Promise<void> {
    const certificates = this.engine.getExpiringCertificates(EXPIRING_QUERY_DAYS);
    const now = Date.now();

    for (const cert of certificates) {
      if (!cert.auto_renew) continue;
      if (cert.not_after === null) continue;
      if (cert.not_after > now + cert.renew_before_days * DAY_MS) continue;

      const entry = this.quarantine.get(cert.secret_id);
      if (entry && now < entry.nextAttemptAt) continue;
      try {
        await this.renewWithRetry(cert.secret_id);
      } catch (err) {
        // One unrenewable certificate must not halt the loop; the host is
        // notified, remaining certificates are still processed.
        this.onRenewError?.(cert.secret_id, err);
      }
    }
  }

  private async renewWithRetry(secretId: string): Promise<void> {
    let lastError: unknown;
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        await this.renewer.renewCertificate(secretId);
        this.quarantine.delete(secretId);
        return;
      } catch (err) {
        lastError = err;
        if (attempt < MAX_RETRIES - 1) {
          const delay = INITIAL_RETRY_DELAY_MS * Math.pow(4, attempt);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }
    this.recordFailure(secretId);
    throw lastError;
  }

  /** Exponential backoff on the check interval, capped at 24 hours. */
  private recordFailure(secretId: string): void {
    const failures = (this.quarantine.get(secretId)?.failures ?? 0) + 1;
    const backoffMs = Math.min(this.checkIntervalMs * Math.pow(2, failures), MAX_QUARANTINE_MS);
    this.quarantine.set(secretId, { failures, nextAttemptAt: Date.now() + backoffMs });
  }

  get isRunning(): boolean {
    return this.intervalId !== null;
  }
}
