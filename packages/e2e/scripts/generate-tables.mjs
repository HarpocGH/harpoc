// Renders the Chapter 6 tables from a committed evidence run.
//
//   node scripts/generate-tables.mjs [records.jsonl] [--out <dir>]
//                                    [--allow-dirty] [--allow-divergence]
//                                    [--allow-multi-commit]
//
// Defaults to this package's own evidence/run.jsonl and preregistration.json.
// Point it at a file in docs/e2e/evidence/ to regenerate the tables for a run
// that is already committed — which is the normal case, since the thesis cites
// the committed pair rather than whatever the working tree last produced.
//
// Output goes to packages/e2e/out/tables/ (git-ignored) unless
// HARPOC_E2E_TABLES_DIR says otherwise; the generated .tex is committed to
// docs/thesis/generated/, per the placement principle (code here, artifacts
// there) and the HARPOC_BENCH_RESULTS_DIR precedent. No code assumes the docs
// repository sits beside this one.
//
// The generator REFUSES to emit from a compromised record set (D12): a dirty
// run, an outcome that diverged from its pre-registration, an expectation that
// never ran, or a record that fits no table. Each refusal has an opt-out flag,
// and using one stamps the caveat into the provenance block so it travels with
// the artifact instead of living in someone's memory.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkGates,
  classify,
  renderMatrixTable,
  renderProvenance,
  renderScenarioTable,
} from "./tables.mjs";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));

function parseArgs(argv) {
  const options = { allowDirty: false, allowDivergence: false, allowMultiCommit: false };
  let records = null;
  let out = null;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--allow-dirty") options.allowDirty = true;
    else if (arg === "--allow-divergence") options.allowDivergence = true;
    else if (arg === "--allow-multi-commit") options.allowMultiCommit = true;
    else if (arg === "--out") out = argv[++i];
    else if (arg.startsWith("--")) {
      console.error(`generate-tables: unknown option "${arg}"`);
      process.exit(2);
    } else if (records === null) records = arg;
    else {
      console.error(`generate-tables: unexpected argument "${arg}"`);
      process.exit(2);
    }
  }
  return { records, out, options };
}

// `interface` is deliberately not required here: pre-Phase-3 records
// legitimately lack it, and the matrix-cell gate in checkGates() catches
// exactly the case where its absence matters (review 2026-08-14, F3).
const REQUIRED_FIELDS = ["scenario", "context", "surface", "arm", "expected", "observed", "commit"];

function readJsonl(path) {
  const text = readFileSync(path, "utf8").trim();
  if (text === "") return [];
  return text.split(/\r?\n/).map((line, i) => {
    let record;
    try {
      record = JSON.parse(line);
    } catch (cause) {
      throw new Error(`malformed evidence record at line ${String(i + 1)} of ${path}`, { cause });
    }
    for (const field of REQUIRED_FIELDS) {
      if (typeof record[field] !== "string" || record[field] === "") {
        throw new Error(
          `evidence record at line ${String(i + 1)} of ${path} has no ${field}: ` +
            "a record the generator cannot key is a table cell that silently disappears",
        );
      }
    }
    return record;
  });
}

const { records: recordsArg, out: outArg, options } = parseArgs(process.argv.slice(2));

const recordsPath = recordsArg ?? join(PACKAGE_ROOT, "evidence", "run.jsonl");
const expectationsPath = join(PACKAGE_ROOT, "preregistration.json");
const outDir = outArg ?? process.env.HARPOC_E2E_TABLES_DIR ?? join(PACKAGE_ROOT, "out", "tables");

let records;
let expectations;
try {
  records = readJsonl(recordsPath);
  expectations = JSON.parse(readFileSync(expectationsPath, "utf8"));
} catch (err) {
  console.error(`generate-tables: ${err instanceof Error ? err.message : String(err)}`);
  console.error("  a run writes evidence/run.jsonl:  pnpm --filter @harpoc/e2e test:e2e");
  process.exit(1);
}

const problems = checkGates(records, expectations, options);
if (problems.length > 0) {
  console.error(
    `generate-tables: refusing to render from ${String(records.length)} record(s) in ${recordsPath}`,
  );
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error(
    "  a table rendered from a compromised record set undoes what pre-registration and the\n" +
      "  commit stamp buy; --allow-dirty / --allow-divergence / --allow-multi-commit stamp\n" +
      "  the caveat instead",
  );
  process.exit(1);
}

const { paired, matrix, transport, other } = classify(records);
mkdirSync(outDir, { recursive: true });
const written = [
  ["scenario-table.tex", renderScenarioTable(paired, expectations)],
  ["matrix-table.tex", renderMatrixTable(matrix, transport)],
  ["provenance.tex", renderProvenance(records, expectations, options)],
];
for (const [name, content] of written) {
  writeFileSync(join(outDir, name), content, "utf8");
}

console.log(`generate-tables: ${String(records.length)} record(s) from ${recordsPath}`);
console.log(
  `  ${String(paired.length)} paired rows, ${String(matrix.length)} matrix cells, ` +
    `${String(transport.length)} transport-coverage cells, ${String(other.length)} excluded`,
);
for (const [name] of written) console.log(`  wrote ${join(outDir, name)}`);
