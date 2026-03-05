/**
 * Defense-in-depth response sanitization.
 * Scans HTTP response bodies for common credential patterns and redacts them.
 */
export class InjectionGuard {
  private static readonly PATTERNS: readonly RegExp[] = [
    /Bearer\s+[A-Za-z0-9._-]{20,}/g,
    /Basic\s+[A-Za-z0-9+/=]{10,}/g,
    /(api[_-]?key|token|secret)[=:]\s*["']?[A-Za-z0-9._-]{16,}/gi,
  ];

  private redactionCount = 0;

  /**
   * Sanitize a response body by replacing known credential patterns.
   * Returns the sanitized string.
   */
  sanitize(body: string): string {
    let result = body;
    for (const pattern of InjectionGuard.PATTERNS) {
      // Reset lastIndex for global regexes
      pattern.lastIndex = 0;
      result = result.replace(pattern, (match) => {
        this.redactionCount++;
        // Preserve the key part for patterns like "api_key=..."
        const colonOrEqual = match.search(/[=:]/);
        if (colonOrEqual !== -1 && !match.startsWith("Bearer") && !match.startsWith("Basic")) {
          return match.slice(0, colonOrEqual + 1) + "[REDACTED]";
        }
        return "[REDACTED]";
      });
    }
    return result;
  }

  /** Number of redactions performed since creation. */
  get totalRedactions(): number {
    return this.redactionCount;
  }
}
