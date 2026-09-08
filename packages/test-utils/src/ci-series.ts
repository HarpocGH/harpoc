/**
 * The CI series lines — the DPAPI protect / unprotect durations and the WMI
 * listing warm-up — reach the job log through `console.error` and are
 * harvested by grep (decisions.md § "The WMI listing series", § "The DPAPI
 * protect series"). This helper keeps that line byte-identical and, on a
 * GitHub Actions runner, also appends it to the job's step summary
 * (`GITHUB_STEP_SUMMARY`), marking it when the judged sample crosses the
 * standing trigger — so a fired trigger shows on the run's summary page
 * without a harvest. The rule itself stays in the record: a warm WMI listing
 * over 60 s (2026-08-29) or a DPAPI call over 60 s (D3, 2026-09-08) is
 * discussed, not before; the legs stay green either way. Durations and
 * outcome texts only — never key material, never a listing's rows.
 */
import { appendFileSync } from "node:fs";

/** The standing trigger: a judged sample over this many ms is discussed (decisions.md, 2026-08-29 and D3 2026-09-08). */
export const SERIES_TRIGGER_MS = 60_000;

export interface SeriesLineOptions {
  /** The sample the rule is judged on, in ms — the warm listing; the slowest DPAPI call. */
  judgedMs: number;
  /** The step-summary file; defaults to `process.env.GITHUB_STEP_SUMMARY`, absent off a runner. */
  summaryPath?: string;
  /** Where the line goes; defaults to `console.error` — the log the harvest greps. */
  print?: (line: string) => void;
}

export interface SeriesLineOutcome {
  /** True when `judgedMs` exceeds `SERIES_TRIGGER_MS`. */
  fired: boolean;
}

/**
 * Prints a series line unchanged, appends it to the step summary when one is
 * configured, and flags a fired trigger in both places. Never throws: a
 * summary that cannot be written is reported on the print channel.
 */
export function recordSeriesLine(line: string, options: SeriesLineOptions): SeriesLineOutcome {
  const print = options.print ?? ((text: string): void => console.error(text));
  const fired = options.judgedMs > SERIES_TRIGGER_MS;
  const verdict = `(judged ${String(options.judgedMs)} ms > ${String(SERIES_TRIGGER_MS)} ms)`;
  print(line);
  if (fired) print(`[series] TRIGGER ${verdict}: ${line}`);
  const summaryPath = options.summaryPath ?? process.env["GITHUB_STEP_SUMMARY"];
  if (summaryPath === undefined || summaryPath === "") return { fired };
  const entry = fired ? `- :warning: **TRIGGER** ${verdict}: \`${line}\`\n` : `- \`${line}\`\n`;
  try {
    appendFileSync(summaryPath, entry);
  } catch (err) {
    print(`[series] summary write failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  return { fired };
}
