/**
 * Times a session-key protector's calls for the CI log (D3, 2026-09-08): the
 * two DPAPI cases run under budgets a loaded windows-latest runner has
 * exceeded (45 s tripped three times, 2026-09-02 → 07), so each protect and
 * unprotect is measured and printed — durations and outcomes only, never key
 * material — and the series in `decisions.md` decides whether a budget moves.
 * Typed structurally so this package never imports `@harpoc/core`.
 */

/** The protector surface the wrapper delegates to — core's `SessionKeyProtector`, structurally. */
export interface TimedProtectorTarget {
  readonly scheme: string;
  protect(key: Uint8Array): Promise<Uint8Array>;
  unprotect(blob: Uint8Array): Promise<Uint8Array>;
}

/** A wrapped protector: the inner one's scheme, every call timed into the timer's line. */
export interface TimedProtector<S extends string> {
  readonly scheme: S;
  protect(key: Uint8Array): Promise<Uint8Array>;
  unprotect(blob: Uint8Array): Promise<Uint8Array>;
}

export interface ProtectorTimer {
  /** Wraps a protector; every wrapped instance reports into the same line. */
  wrap<S extends string>(inner: TimedProtectorTarget & { readonly scheme: S }): TimedProtector<S>;
  /** One line for the CI log, the calls in order: `[label] protect=1234ms (ok), unprotect=980ms (ok)`. */
  report(): string;
  /** The slowest call so far in ms, failed calls included; 0 before any call — the sample the series trigger is judged on. */
  slowestMs(): number;
}

export function protectorTimer(label: string): ProtectorTimer {
  const samples: string[] = [];
  let slowest = 0;
  const timed = async <S extends string>(
    inner: TimedProtectorTarget & { readonly scheme: S },
    method: "protect" | "unprotect",
    input: Uint8Array,
  ): Promise<Uint8Array> => {
    const started = Date.now();
    const record = (outcome: string): void => {
      const elapsed = Date.now() - started;
      slowest = Math.max(slowest, elapsed);
      samples.push(`${method}=${String(elapsed)}ms (${outcome})`);
    };
    try {
      const output = await inner[method](input);
      record("ok");
      return output;
    } catch (err) {
      record(err instanceof Error ? err.message : String(err));
      throw err;
    }
  };
  return {
    wrap: (inner) => ({
      scheme: inner.scheme,
      protect: (key) => timed(inner, "protect", key),
      unprotect: (blob) => timed(inner, "unprotect", blob),
    }),
    report: () => `[${label}] ${samples.length === 0 ? "no calls" : samples.join(", ")}`,
    slowestMs: () => slowest,
  };
}
