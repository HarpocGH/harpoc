import { afterEach, beforeEach } from "vitest";

const AUDIT_TAG = "[audit] ";

/**
 * Call once at the top of a test file that serves the REST app, or as the
 * first statement of the describe that serves it: every test in that scope
 * runs with the audit middleware's per-request `[audit] …` line kept off
 * stderr. Every other `console.error` call reaches the function that was
 * there before, so a real error stays visible and a test may still spy on it.
 */
export function silenceAuditLines(): void {
  let replaced: typeof console.error | undefined;

  beforeEach(() => {
    const previous = console.error;
    replaced = previous;
    console.error = (...args: unknown[]): void => {
      const first = args[0];
      if (typeof first === "string" && first.startsWith(AUDIT_TAG)) return;
      previous.apply(console, args);
    };
  });

  afterEach(() => {
    if (replaced !== undefined) console.error = replaced;
    replaced = undefined;
  });
}
