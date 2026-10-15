// CLI over recheck.mjs: `pnpm --filter @harpoc/e2e recheck [--require-calls] [<run.jsonl>]`.
// The path is resolved against the directory the command was typed in (pnpm's
// INIT_CWD; the process cwd under bare node), and defaults to this package's
// evidence/run.jsonl. Exits 1 on an inconsistency, and — under --require-calls —
// when any record carries no `calls` or carries a truncated or elided one: a
// committed pair since 2026-10-15 must be re-checkable whole on every record.
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readJsonl, recheck, renderRecheck } from "./recheck.mjs";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));
const BASE = process.env.INIT_CWD ?? process.cwd();

let path = null;
let requireCalls = false;
for (const arg of process.argv.slice(2)) {
  if (arg === "--require-calls") requireCalls = true;
  else if (arg.startsWith("--")) {
    console.error(`recheck: unknown option "${arg}"`);
    process.exit(2);
  } else if (path === null) path = resolve(BASE, arg);
  else {
    console.error(`recheck: unexpected argument "${arg}"`);
    process.exit(2);
  }
}

let records;
try {
  records = readJsonl(path ?? join(PACKAGE_ROOT, "evidence", "run.jsonl"));
} catch (err) {
  console.error(`recheck: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

const out = recheck(records);
console.log(renderRecheck(out));
const incomplete = out.unchecked > 0 || out.partial > 0;
process.exit(out.inconsistent.length > 0 || (requireCalls && incomplete) ? 1 : 0);
