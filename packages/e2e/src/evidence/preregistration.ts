import { readFileSync } from "node:fs";

export interface Expectation {
  scenario: string;
  context: string;
  /**
   * Distinguishes arms of one scenario that agree on scenario+context+surface+arm.
   * Output-channel leakage runs ten such arms; without this dimension they
   * collide onto a single key and nine of them silently read the tenth's
   * expectation. Absent is its own key, never a wildcard — an arm that forgets
   * its variant must fail to resolve, not match something adjacent.
   */
  variant?: string;
  surface: string;
  arm: "baseline" | "harpoc";
  /**
   * Set ONLY where the platform behaviour is itself the designed outcome
   * (R-1 obligation 2) — network isolation refusing with
   * NETWORK_ISOLATION_UNAVAILABLE on Windows is the first such case. An
   * OS-keyed row wins over the OS-agnostic row of the same key; everything
   * else stays OS-agnostic, because "outcomes match on every OS" is the
   * property under test and a per-OS expectation would assume it away.
   */
  host_os?: string;
  expected: string;
}

export type ExpectationKey = Omit<Expectation, "expected" | "host_os">;

function keyOf(k: ExpectationKey): string {
  return `${k.scenario}|${k.context}|${k.variant ?? ""}|${k.surface}|${k.arm}`;
}

export function loadExpectations(filePath: string): Expectation[] {
  const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
  if (!Array.isArray(parsed)) {
    throw new Error(`malformed pre-registration: ${filePath} is not an array`);
  }

  return parsed.map((row, i) => {
    const r = row as Partial<Expectation>;
    const ok =
      typeof r.scenario === "string" &&
      typeof r.context === "string" &&
      typeof r.surface === "string" &&
      (r.arm === "baseline" || r.arm === "harpoc") &&
      typeof r.expected === "string" &&
      (r.variant === undefined || typeof r.variant === "string") &&
      (r.host_os === undefined || typeof r.host_os === "string");
    if (!ok) throw new Error(`malformed pre-registration row at index ${i} in ${filePath}`);
    return r as Expectation;
  });
}

/**
 * Structural problems with the expectation SET, as opposed to a single row.
 *
 * All three fail silently: a corrupted set still yields a green run and a
 * plausible table, which is the worst way for evidence to be wrong. Returns
 * human-readable problems rather than throwing, so a caller can report all of
 * them at once.
 */
export function validateExpectationSet(expectations: Expectation[]): string[] {
  const problems: string[] = [];

  // 1. Duplicates. `expectationFor` resolves with `find`, so a second row for
  //    the same key is dead code — and if the two disagree, whichever was
  //    written first silently decides the outcome.
  const counts = new Map<string, number>();
  for (const e of expectations) {
    const k = `${keyOf(e)}|${e.host_os ?? ""}`;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  for (const [k, n] of counts) {
    if (n > 1) problems.push(`duplicate expectation key (${String(n)}x): ${k}`);
  }

  // 2. An OS-keyed row with no OS-agnostic sibling. Every other platform would
  //    then fail to resolve mid-run, and the arm would carry an expectation on
  //    exactly one OS — the opposite of R-1's "outcomes must match across
  //    operating systems, except where the platform behaviour IS the outcome".
  const agnostic = new Set(
    expectations.filter((e) => e.host_os === undefined).map((e) => keyOf(e)),
  );
  for (const e of expectations) {
    if (e.host_os !== undefined && !agnostic.has(keyOf(e))) {
      problems.push(`os-keyed expectation without an OS-agnostic sibling: ${keyOf(e)}`);
    }
  }

  // 3. A paired arm registered for only one side — the failure mode C-3 exists
  //    to prevent. Scoped to rows carrying a `variant`: those are the two-arm
  //    attack scenarios, whereas the Phase 1-3 demonstration rows are
  //    single-arm by construction and predate C-3. A variant-bearing row that
  //    lacks its pair is worth flagging whenever it appears.
  const arms = new Map<string, Set<string>>();
  for (const e of expectations) {
    if (e.variant === undefined) continue;
    const k = `${e.scenario}|${e.context}|${e.variant}|${e.surface}`;
    let present = arms.get(k);
    if (present === undefined) {
      present = new Set<string>();
      arms.set(k, present);
    }
    present.add(e.arm);
  }
  for (const [k, present] of arms) {
    if (present.size < 2) {
      const missing = present.has("baseline") ? "harpoc" : "baseline";
      problems.push(`scenario arm lacks both arms (${missing} missing): ${k}`);
    }
  }

  return problems;
}

/**
 * Look up the outcome fixed before the run. An unregistered combination is an
 * error, not a default — that is what stops an outcome from being invented
 * after it was observed.
 *
 * `os` is a parameter rather than a read of `process.platform` so the
 * resolution order is testable on one host; production callers take the
 * default.
 */
export function expectationFor(
  expectations: Expectation[],
  key: ExpectationKey,
  os: string = process.platform,
): string {
  const wanted = keyOf(key);
  const matching = expectations.filter((e) => keyOf(e) === wanted);
  // An OS-keyed row wins over the OS-agnostic one wherever both exist, at any
  // position in the file — file order must not decide an outcome.
  const found =
    matching.find((e) => e.host_os === os) ?? matching.find((e) => e.host_os === undefined);
  if (!found) throw new Error(`outcome is not pre-registered: ${wanted} (host_os=${os})`);
  return found.expected;
}
