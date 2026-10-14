// P0 gate: the harness times a known quantity plausibly and stats hold their invariants;
// the (c′) REST leg answers once through a scoped token.

import { restLeg, startEchoServer } from "../bench-http.mjs";
import { assertSane, isMain, measure, sleep, stats } from "./harness.mjs";
import { createBenchSecret, createVault } from "./vault-fixture.mjs";

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

const fx = await createVault();
const echo = await startEchoServer();
try {
  const handle = await createBenchSecret(
    fx.engine,
    "bench-selftest",
    Buffer.from("selftest", "utf8"),
  );
  await fx.engine.setInjectionPolicy(handle, { url_allowlist: [echo.url] });
  const action = { type: "http", method: "GET", url: echo.url, injection: { type: "bearer" } };
  await restLeg(fx.engine, handle, action);
  assertSane(echo.getCount() === 1, `REST probe reached the server ${echo.getCount()} times`);
} finally {
  await echo.close();
  await fx.cleanup();
}

console.log(
  `harness selftest OK — 5 ms sleep measured at median ${s.medianMs} ms (p95 ${s.p95Ms} ms); (c′) REST leg answered 200`,
);
