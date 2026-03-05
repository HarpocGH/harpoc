import {
  ErrorCode,
  RATE_LIMIT_GLOBAL,
  RATE_LIMIT_PER_SECRET,
  RATE_LIMIT_USE_SECRET,
  VaultError,
} from "@harpoc/shared";

interface Bucket {
  tokens: number;
  lastRefill: number;
}

/**
 * Token-bucket rate limiter with two tiers: global and per-secret.
 * All limits are per-minute. Buckets auto-decay (refill over time).
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

  checkLimit(secretId?: string, isUseSecret = false): void {
    this.refill(this.globalBucket, this.globalLimit);
    if (this.globalBucket.tokens <= 0) {
      throw new VaultError(ErrorCode.RATE_LIMIT_EXCEEDED, "Global rate limit exceeded");
    }
    this.globalBucket.tokens--;

    if (secretId) {
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
  }

  private refill(bucket: Bucket, limit: number): void {
    const now = Date.now();
    const elapsed = now - bucket.lastRefill;
    const tokensToAdd = Math.floor((elapsed / 60_000) * limit);
    if (tokensToAdd > 0) {
      bucket.tokens = Math.min(limit, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
    }

    // Evict idle secret buckets that are fully refilled
    if (this.secretBuckets.size > 1000) {
      for (const [id, b] of this.secretBuckets) {
        if (b.tokens >= this.perSecretLimit) {
          this.secretBuckets.delete(id);
        }
      }
    }
  }
}
