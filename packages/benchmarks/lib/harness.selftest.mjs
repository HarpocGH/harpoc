// P0 gate: the harness times a known quantity plausibly and stats hold their invariants.

import { assertSane, isMain, measure, sleep, stats } from "./harness.mjs";

const ns = await measure(() => sleep(5), { samples: 20, warmup: 3 });
const s = stats(ns);

assertSane(s.samples === 20, `expected 20 samples, got ${s.samples}`);
assertSane(
  s.medianMs >= 3 && s.medianMs <= 100,
  `median ${s.medianMs} ms outside [3, 100] for a 5 ms sleep`,
);
assertSane(
  s.minMs <= s.medianMs && s.medianMs <= s.p95Ms && s.p95Ms <= s.maxMs,
  "stat ordering violated",
);
assertSane(isMain(import.meta), "isMain() failed for the entry module");

console.log(
  `harness selftest OK — 5 ms sleep measured at median ${s.medianMs} ms (p95 ${s.p95Ms} ms)`,
);
