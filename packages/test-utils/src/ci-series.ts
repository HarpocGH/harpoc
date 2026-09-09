/**
 * The CI series lines — the DPAPI protect / unprotect durations and the WMI
 * listing warm-up — reach the job log through `console.error` and are
 * harvested by grep (decisions.md § "The WMI listing series", § "The DPAPI
 * protect series"). This helper keeps that line byte-identical and, on a
 * GitHub Actions runner, also appends it to the job's step summary
 * (`GITHUB_STEP_SUMMARY`) and to the series file the Windows legs upload as
 * an artifact (`HARPOC_SERIES_FILE`, 2026-09-09), marking it when the judged
 * sample crosses the standing trigger — so a fired trigger shows on the run's
 * summary page and in `gh run download`'s file without a harvest or a
 * browser. The rule itself stays in the record: a warm WMI listing
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
  /**
   * The series file the Windows legs upload as an artifact (D5, 2026-09-09);
   * defaults to `process.env.HARPOC_SERIES_FILE`, set by `ci.yml`'s Windows
   * test step and named in `turbo.json`'s `test.env`; absent elsewhere.
   */
  seriesPath?: string;
  /** Where the line goes; defaults to `console.error` — the log the harvest greps. */
  print?: (line: string) => void;
}

export interface SeriesLineOutcome {
  /** True when `judgedMs` exceeds `SERIES_TRIGGER_MS`. */
  fired: boolean;
}

/**
 * Prints a series line unchanged, appends it to the step summary and to the
 * series file when either is configured, and flags a fired trigger in every
 * place. Never throws: a sink that cannot be written is reported on the print
 * channel, and the other sink is still written.
 */
export function recordSeriesLine(line: string, options: SeriesLineOptions): SeriesLineOutcome {
  const print = options.print ?? ((text: string): void => console.error(text));
  const fired = options.judgedMs > SERIES_TRIGGER_MS;
  const verdict = `(judged ${String(options.judgedMs)} ms > ${String(SERIES_TRIGGER_MS)} ms)`;
  print(line);
  if (fired) print(`[series] TRIGGER ${verdict}: ${line}`);
  const entry = fired ? `- :warning: **TRIGGER** ${verdict}: \`${line}\`\n` : `- \`${line}\`\n`;
  const sinks: ReadonlyArray<readonly [name: string, path: string | undefined]> = [
    ["summary", options.summaryPath ?? process.env["GITHUB_STEP_SUMMARY"]],
    ["series file", options.seriesPath ?? process.env["HARPOC_SERIES_FILE"]],
  ];
  for (const [name, path] of sinks) {
    if (path === undefined || path === "") continue;
    try {
      appendFileSync(path, entry);
    } catch (err) {
      print(`[series] ${name} write failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { fired };
}
