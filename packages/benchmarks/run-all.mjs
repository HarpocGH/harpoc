// Runs every scenario and writes environment-stamped results to results/.
// Usage: node run-all.mjs [--cli] [--remote-url <https://…>] [--suffix <name>]

import { captureEnv } from "./lib/env-info.mjs";
import { printScenario, resultsBaseName, writeResults } from "./lib/report.mjs";
import { run as httpRun } from "./bench-http.mjs";
import { run as secretReadRun } from "./bench-secret-read.mjs";
import { run as sessionLoadRun } from "./bench-session-load.mjs";
import { run as unlockRun } from "./bench-unlock.mjs";

const cli = process.argv.includes("--cli");
const remoteIdx = process.argv.indexOf("--remote-url");
const remoteUrl = remoteIdx !== -1 ? process.argv[remoteIdx + 1] : undefined;
const suffixIdx = process.argv.indexOf("--suffix");
const suffix = suffixIdx !== -1 ? (process.argv[suffixIdx + 1] ?? "") : undefined;
const suffixForms = process.argv.filter((arg) => arg === "--suffix" || arg.startsWith("--suffix="));
if (suffixForms.length > 1 || suffixForms.some((arg) => arg.startsWith("--suffix="))) {
  throw new Error("--suffix takes one value as a separate argument: --suffix <name>");
}

const plan = [
  ["secret-read", () => secretReadRun()],
  ["unlock", () => unlockRun()],
  ["http-end-to-end", () => httpRun({ remoteUrl })],
  ["session-load", () => sessionLoadRun({ cli })],
];

const env = captureEnv();
// A refused suffix fails here, before the scenarios run, not at the write.
resultsBaseName(env, { suffix });
console.log(
  `# Harpoc baseline latency run — ${env.hostname}, repo ${env.repo_commit}, Node ${env.node}\n`,
);

const results = [];
for (const [name, fn] of plan) {
  console.log(`## running: ${name} …\n`);
  const result = await fn();
  results.push(result);
  printScenario(result);
}

const { jsonPath, mdPath } = writeResults(env, results, { suffix });
console.log(`results written:\n  ${jsonPath}\n  ${mdPath}`);
