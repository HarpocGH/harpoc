import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SERIES_TRIGGER_MS, recordSeriesLine } from "./ci-series.js";

const LINE = "[t dpapi] protect=1234ms (ok), unprotect=980ms (ok)";
const savedSummary = process.env["GITHUB_STEP_SUMMARY"];
const savedSeries = process.env["HARPOC_SERIES_FILE"];
let dir: string;

beforeEach(() => {
  delete process.env["GITHUB_STEP_SUMMARY"];
  delete process.env["HARPOC_SERIES_FILE"];
  dir = mkdtempSync(join(tmpdir(), "harpoc-series-"));
});

afterEach(() => {
  if (savedSummary === undefined) delete process.env["GITHUB_STEP_SUMMARY"];
  else process.env["GITHUB_STEP_SUMMARY"] = savedSummary;
  if (savedSeries === undefined) delete process.env["HARPOC_SERIES_FILE"];
  else process.env["HARPOC_SERIES_FILE"] = savedSeries;
  rmSync(dir, { recursive: true, force: true });
});

describe("recordSeriesLine (D4, 2026-09-08)", () => {
  it("prints the line byte-identical and writes no summary when none is configured", () => {
    const printed: string[] = [];
    const outcome = recordSeriesLine(LINE, {
      judgedMs: 1234,
      print: (l) => printed.push(l),
    });
    expect(printed).toEqual([LINE]);
    expect(outcome).toEqual({ fired: false });
  });

  it("appends each line as a bullet to the configured summary file", () => {
    const summary = join(dir, "summary.md");
    const printed: string[] = [];
    recordSeriesLine(LINE, {
      judgedMs: 1234,
      summaryPath: summary,
      print: (l) => printed.push(l),
    });
    recordSeriesLine("second", {
      judgedMs: 1,
      summaryPath: summary,
      print: (l) => printed.push(l),
    });
    expect(readFileSync(summary, "utf8")).toBe(`- \`${LINE}\`\n- \`second\`\n`);
    expect(printed).toEqual([LINE, "second"]);
  });

  it("takes the summary path from GITHUB_STEP_SUMMARY when none is passed", () => {
    const summary = join(dir, "env-summary.md");
    process.env["GITHUB_STEP_SUMMARY"] = summary;
    recordSeriesLine(LINE, { judgedMs: 5, print: () => undefined });
    expect(readFileSync(summary, "utf8")).toBe(`- \`${LINE}\`\n`);
  });

  it("marks a judged sample over the trigger in the summary and on the print channel", () => {
    const summary = join(dir, "fired.md");
    const printed: string[] = [];
    const outcome = recordSeriesLine(LINE, {
      judgedMs: SERIES_TRIGGER_MS + 1,
      summaryPath: summary,
      print: (l) => printed.push(l),
    });
    expect(outcome).toEqual({ fired: true });
    expect(printed[0]).toBe(LINE);
    expect(printed[1]).toBe(`[series] TRIGGER (judged 60001 ms > 60000 ms): ${LINE}`);
    expect(readFileSync(summary, "utf8")).toBe(
      `- :warning: **TRIGGER** (judged 60001 ms > 60000 ms): \`${LINE}\`\n`,
    );
  });

  it("a sample at the trigger does not fire", () => {
    const printed: string[] = [];
    const outcome = recordSeriesLine(LINE, {
      judgedMs: SERIES_TRIGGER_MS,
      print: (l) => printed.push(l),
    });
    expect(outcome).toEqual({ fired: false });
    expect(printed).toEqual([LINE]);
  });

  it("reports a summary it cannot write on the print channel and never throws", () => {
    const printed: string[] = [];
    const outcome = recordSeriesLine(LINE, {
      judgedMs: 1,
      summaryPath: join(dir, "missing", "dir", "summary.md"),
      print: (l) => printed.push(l),
    });
    expect(outcome).toEqual({ fired: false });
    expect(printed[0]).toBe(LINE);
    expect(printed[1]).toMatch(/^\[series\] summary write failed: /);
  });

  it("appends the identical entry to the series file beside the summary (D5, 2026-09-09)", () => {
    const summary = join(dir, "summary.md");
    const series = join(dir, "series.md");
    const printed: string[] = [];
    recordSeriesLine(LINE, {
      judgedMs: SERIES_TRIGGER_MS + 1,
      summaryPath: summary,
      seriesPath: series,
      print: (l) => printed.push(l),
    });
    recordSeriesLine("second", {
      judgedMs: 1,
      summaryPath: summary,
      seriesPath: series,
      print: (l) => printed.push(l),
    });
    const expected = `- :warning: **TRIGGER** (judged 60001 ms > 60000 ms): \`${LINE}\`\n- \`second\`\n`;
    expect(readFileSync(series, "utf8")).toBe(expected);
    expect(readFileSync(summary, "utf8")).toBe(expected);
    expect(printed).toEqual([
      LINE,
      `[series] TRIGGER (judged 60001 ms > 60000 ms): ${LINE}`,
      "second",
    ]);
  });

  it("takes the series file from HARPOC_SERIES_FILE when none is passed, and writes no summary without one", () => {
    const series = join(dir, "env-series.md");
    process.env["HARPOC_SERIES_FILE"] = series;
    const printed: string[] = [];
    recordSeriesLine(LINE, { judgedMs: 5, print: (l) => printed.push(l) });
    expect(readFileSync(series, "utf8")).toBe(`- \`${LINE}\`\n`);
    expect(existsSync(join(dir, "summary.md"))).toBe(false);
    expect(printed).toEqual([LINE]);
  });

  it("reports a series file it cannot write on the print channel, still writes the summary, and never throws", () => {
    const summary = join(dir, "summary.md");
    const printed: string[] = [];
    const outcome = recordSeriesLine(LINE, {
      judgedMs: 1,
      summaryPath: summary,
      seriesPath: join(dir, "missing", "dir", "series.md"),
      print: (l) => printed.push(l),
    });
    expect(outcome).toEqual({ fired: false });
    expect(readFileSync(summary, "utf8")).toBe(`- \`${LINE}\`\n`);
    expect(printed[0]).toBe(LINE);
    expect(printed[1]).toMatch(/^\[series\] series file write failed: /);
    expect(printed).toHaveLength(2);
  });
});
