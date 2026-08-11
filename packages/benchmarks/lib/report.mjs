// Result reporting — stdout tables for standalone runs, JSON + markdown files for run-all.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Results are thesis artifacts and live in the docs repository, not here: a run
// lands in this (git-ignored) directory, and a run worth citing is written
// straight into docs/benchmarks/results/ by pointing this at it. Kept as an
// environment variable rather than a committed relative path so no code in this
// repository depends on the docs repository sitting beside it.
export const RESULTS_DIR = process.env.HARPOC_BENCH_RESULTS_DIR ?? join(HERE, "..", "results");

const STAT_HEADER = "| measurement | median | p95 | min | max | mean ± sd | samples |";
const STAT_DIVIDER = "|---|---|---|---|---|---|---|";

function ms(x) {
  return `${x.toFixed(x >= 100 ? 0 : x >= 10 ? 1 : 3)} ms`;
}

function statRow(label, s) {
  return `| ${label} | ${ms(s.medianMs)} | ${ms(s.p95Ms)} | ${ms(s.minMs)} | ${ms(s.maxMs)} | ${ms(s.meanMs)} ± ${ms(s.sdMs)} | ${s.samples} |`;
}

/** Render one scenario result as a markdown fragment. */
export function scenarioMarkdown(result) {
  const lines = [`### ${result.scenario} — ${result.thesis}`, ""];
  if (result.skipped) {
    lines.push(`_Skipped: ${result.reason}_`, "");
    return lines.join("\n");
  }
  lines.push(STAT_HEADER, STAT_DIVIDER);
  for (const [label, s] of Object.entries(result.metrics)) {
    lines.push(statRow(label, s));
  }
  lines.push("");
  for (const note of result.notes ?? []) {
    lines.push(`- ${note}`);
  }
  lines.push("");
  return lines.join("\n");
}

export function envMarkdown(env) {
  return [
    "| environment | value |",
    "|---|---|",
    `| timestamp | ${env.timestamp} |`,
    `| host | ${env.hostname} (${env.platform} ${env.os_release}, ${env.arch}) |`,
    `| CPU | ${env.cpu} (${env.cores} logical cores) |`,
    `| RAM | ${env.memory_gib} GiB |`,
    `| Node | ${env.node} |`,
    `| repo commit | ${env.repo_commit} |`,
    "",
  ].join("\n");
}

export function printScenario(result) {
  console.log(scenarioMarkdown(result));
}

/** Write the combined results of a run-all invocation. Returns the file paths. */
export function writeResults(env, results) {
  mkdirSync(RESULTS_DIR, { recursive: true });
  const stamp = env.timestamp.slice(0, 10);
  const base = `${stamp}-${env.hostname.toLowerCase()}`;
  const jsonPath = join(RESULTS_DIR, `${base}.json`);
  const mdPath = join(RESULTS_DIR, `${base}.md`);

  writeFileSync(jsonPath, `${JSON.stringify({ env, results }, null, 2)}\n`, "utf8");

  const md = [
    `# Harpoc baseline latency — ${stamp} (${env.hostname})`,
    "",
    "Produced by `packages/benchmarks/run-all.mjs` in the code repository. Scenario → thesis mapping: (a)–(c) feed",
    "Ch. 6 §Baseline Performance; (d) reproduces the Ch. 5 § Session File DPAPI figure.",
    "",
    envMarkdown(env),
    ...results.map(scenarioMarkdown),
  ].join("\n");
  writeFileSync(mdPath, md, "utf8");

  return { jsonPath, mdPath };
}
