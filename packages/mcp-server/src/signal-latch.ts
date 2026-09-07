import type { ServerStopTrigger } from "@harpoc/shared";

/** The two signals a launcher stops `harpoc-mcp` with. */
const STOP_SIGNALS = ["SIGINT", "SIGTERM"] as const satisfies readonly ServerStopTrigger[];

export type StopSignal = (typeof STOP_SIGNALS)[number];

/** What the latch listens on — `process`, or an emitter in a test. */
export interface SignalSource {
  on(event: StopSignal, listener: () => void): unknown;
  off(event: StopSignal, listener: () => void): unknown;
}

export interface SignalLatch {
  /** The first stop signal seen before `arm`, or `null`. */
  pending(): StopSignal | null;
  /**
   * Hand every signal to `handler` from now on. A signal already pending is
   * delivered synchronously, before `arm` returns.
   */
  arm(handler: (trigger: StopSignal) => void): void;
  /** Detach both listeners (a test seam; `main()` never disposes). */
  dispose(): void;
}

/**
 * Registered as the first act of `main()`, so a stop that arrives while the
 * session loads or the transport comes up meets a handler rather than the
 * signal's default disposition (D8, 2026-09-07). Until `arm`, the latch only
 * remembers the first signal — `main()` reads it at its checkpoints; after
 * `arm`, every signal goes straight to the handler.
 */
export function installSignalLatch(source: SignalSource = process): SignalLatch {
  let pending: StopSignal | null = null;
  let handler: ((trigger: StopSignal) => void) | null = null;
  const listeners = new Map<StopSignal, () => void>();

  for (const signal of STOP_SIGNALS) {
    const listener = (): void => {
      if (handler !== null) {
        handler(signal);
        return;
      }
      pending ??= signal;
    };
    listeners.set(signal, listener);
    source.on(signal, listener);
  }

  return {
    pending: () => pending,
    arm(next) {
      handler = next;
      if (pending !== null) next(pending);
    },
    dispose() {
      for (const [signal, listener] of listeners) source.off(signal, listener);
    },
  };
}
