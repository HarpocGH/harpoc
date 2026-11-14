import { RATE_LIMIT_GLOBAL, RATE_LIMIT_PER_SECRET, RATE_LIMIT_USE_SECRET } from "./constants.js";
import { ErrorCode, VaultError } from "./errors.js";

interface Bucket {
  tokens: number;
  lastRefill: number;
}

/**
 * Token-bucket rate limiter with two tiers: global and per-secret. All limits
 * are per-minute; buckets refill continuously. The one implementation behind
 * the REST middleware (`checkGlobal` per request, `checkSecret` per route), the
 * MCP tools (`checkLimit` — both tiers in one call) and the egress proxy
 * (`checkSecret(handle, true)` per brokered request): the REST and MCP twins
 * this replaces had drifted once already (L8, the eviction sweep).
 */
export class RateLimiter {
  private readonly globalBucket: Bucket;
  private readonly secretBuckets = new Map<string, Bucket>();

  constructor(
    private readonly globalLimit = RATE_LIMIT_GLOBAL,
    private readonly perSecretLimit = RATE_LIMIT_PER_SECRET,
    private readonly useSecretLimit = RATE_LIMIT_USE_SECRET,
  ) {
    this.globalBucket = { tokens: globalLimit, lastRefill: Date.now() };
  }

  checkGlobal(): void {
    this.refill(this.globalBucket, this.globalLimit);
    if (this.globalBucket.tokens <= 0) {
      throw new VaultError(ErrorCode.RATE_LIMIT_EXCEEDED, "Global rate limit exceeded");
    }
    this.globalBucket.tokens--;
  }

  checkSecret(secretId: string, isUseSecret = false): void {
    const limit = isUseSecret ? this.useSecretLimit : this.perSecretLimit;
    let bucket = this.secretBuckets.get(secretId);
    if (!bucket) {
      bucket = { tokens: limit, lastRefill: Date.now() };
      this.secretBuckets.set(secretId, bucket);
    }
    this.refill(bucket, limit);
    if (bucket.tokens <= 0) {
      throw new VaultError(ErrorCode.RATE_LIMIT_EXCEEDED, "Per-secret rate limit exceeded");
    }
    bucket.tokens--;
  }

  /** Both tiers in one call: the global bucket, then the secret's when one is named. */
  checkLimit(secretId?: string, isUseSecret = false): void {
    this.checkGlobal();
    if (secretId) this.checkSecret(secretId, isUseSecret);
  }

  private refill(bucket: Bucket, limit: number): void {
    const now = Date.now();
    const elapsed = now - bucket.lastRefill;
    const tokensToAdd = Math.floor((elapsed / 60_000) * limit);
    if (tokensToAdd > 0) {
      bucket.tokens = Math.min(limit, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
    }

    // Evict idle secret buckets once the map is large. The in-flight bucket
    // must be skipped — deleting it before `bucket.tokens--` silently stopped
    // per-secret limiting — and the refill must be *computed*, since stored
    // tokens never reach the limit (every access decrements after refill) and
    // idle buckets are never refilled, so testing the stored value alone
    // evicted nothing, ever (L8).
    if (this.secretBuckets.size > 1000) {
      const sweepLimit = Math.max(this.perSecretLimit, this.useSecretLimit);
      for (const [id, b] of this.secretBuckets) {
        if (b === bucket) continue; // the in-flight bucket is decremented next
        const idleRefill = Math.floor(((now - b.lastRefill) / 60_000) * sweepLimit);
        if (b.tokens + idleRefill >= sweepLimit) {
          this.secretBuckets.delete(id);
        }
      }
    }
  }
}
