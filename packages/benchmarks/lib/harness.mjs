// Timing harness — plain Node ESM, no dependencies.
// All raw timings are nanoseconds (process.hrtime.bigint); stats convert to ms.

import { pathToFileURL } from "node:url";

/**
 * Run `op` (warmup + samples) times, timing only `op` itself.
 * `beforeEach` (untimed) runs before every iteration, warmup included.
 * Returns the array of sampled durations in nanoseconds.
 */
export async function measure(op, { samples, warmup = 0, beforeEach } = {}) {
  const ns = [];
  const total = warmup + samples;
  for (let i = 0; i < total; i++) {
    if (beforeEach) await beforeEach(i);
    const t0 = process.hrtime.bigint();
    await op(i);
    const t1 = process.hrtime.bigint();
    if (i >= warmup) ns.push(Number(t1 - t0));
  }
  return ns;
}

/** median / p95 (nearest-rank) / min / max / mean ± sd, all in milliseconds. */
export function stats(ns) {
  if (!Array.isArray(ns) || ns.length === 0) throw new Error("stats: empty sample set");
  const ms = ns.map((n) => n / 1e6).sort((a, b) => a - b);
  const n = ms.length;
  const median = n % 2 === 1 ? ms[(n - 1) / 2] : (ms[n / 2 - 1] + ms[n / 2]) / 2;
  const p95 = ms[Math.max(0, Math.ceil(0.95 * n) - 1)];
  const mean = ms.reduce((s, v) => s + v, 0) / n;
  const sd = n > 1 ? Math.sqrt(ms.reduce((s, v) => s + (v - mean) ** 2, 0) / (n - 1)) : 0;
  return {
    samples: n,
    medianMs: round(median),
    p95Ms: round(p95),
    minMs: round(ms[0]),
    maxMs: round(ms[n - 1]),
    meanMs: round(mean),
    sdMs: round(sd),
  };
}

function round(x) {
  return Math.round(x * 1000) / 1000;
}

/** Fail loudly when a measured number is implausible (miswired benchmark). */
export function assertSane(condition, message) {
  if (!condition) throw new Error(`sanity check failed: ${message}`);
}

/** True when `importMeta` belongs to the module Node was started with. */
export function isMain(importMeta) {
  if (!process.argv[1]) return false;
  return importMeta.url === pathToFileURL(process.argv[1]).href;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
