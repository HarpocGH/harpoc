import type { ServerStopTrigger } from "@harpoc/shared";

/** The two signals a launcher stops `harpoc-mcp` with. */
const STOP_SIGNALS = ["SIGINT", "SIGTERM"] as const satisfies readonly ServerStopTrigger[];

export type StopSignal = (typeof STOP_SIGNALS)[number];

/**
 * The exit code of a second stop signal before readiness: the shell
 * convention `128 + signo` (SIGINT 2, SIGTERM 15) — the code a process ends
 * with under the signal's default disposition, which is what the second
 * signal restores (2026-09-07).
 */
export const REPEAT_EXIT_CODES: Readonly<Record<StopSignal, number>> = {
  SIGINT: 130,
  SIGTERM: 143,
};

/** The one stderr line the default escalation writes before it exits. */
export function repeatStopLine(trigger: StopSignal): string {
  return `harpoc-mcp: a second ${trigger} arrived during start-up, stopping now (exit ${String(REPEAT_EXIT_CODES[trigger])})\n`;
}

function exitOnRepeat(trigger: StopSignal): void {
  process.stderr.write(repeatStopLine(trigger));
  process.exit(REPEAT_EXIT_CODES[trigger]);
}

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
 * signal's default disposition (D8, 2026-09-07). Until `arm`, the latch
 * remembers the first signal only — `main()` reads it at its checkpoints —
 * and hands every further signal to `onRepeat`: by default one stderr line
 * and `process.exit(128 + signo)`, so a start-up stalled in the session load
 * (a keystore helper at its 15 s bound) is not `SIGKILL`-only. Nothing is
 * recorded before `loadSession` returns, so an exit there orphans no audit
 * row; a helper still running is abandoned, and ends on its own once its
 * stdout pipe is gone. The escalation stays live until `arm`, so two signals
 * landing in the milliseconds between the transport's `server.start` row
 * and the arming end the process with that row unpaired — the outcome the
 * default disposition or a crash leaves as well (accepted, 2026-09-07).
 * After `arm`, every signal goes straight to the handler.
 */
export function installSignalLatch(
  source: SignalSource = process,
  onRepeat: (trigger: StopSignal) => void = exitOnRepeat,
): SignalLatch {
  let pending: StopSignal | null = null;
  let handler: ((trigger: StopSignal) => void) | null = null;
  const listeners = new Map<StopSignal, () => void>();

  for (const signal of STOP_SIGNALS) {
    const listener = (): void => {
      if (handler !== null) {
        handler(signal);
        return;
      }
      if (pending !== null) {
        onRepeat(signal);
        return;
      }
      pending = signal;
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
