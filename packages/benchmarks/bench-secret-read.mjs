// Scenario (a) — per-use_secret overhead: SQLite read + decrypt.
// Thesis: Ch. 6 §Baseline Performance. VaultEngine.getSecretValue() is exactly
// the value-resolution path useSecret() itself calls (HMAC name lookup →
// SQLite row read → DEK unwrap → AES-256-GCM decrypt), plus the access audit
// write every value read produces by design.

import { assertSane, isMain, measure, stats } from "./lib/harness.mjs";
import { printScenario } from "./lib/report.mjs";
import { createBenchSecret, createVault, wipeBuffer } from "./lib/vault-fixture.mjs";

import { randomBytes } from "node:crypto";

const SAMPLES = 200;
const WARMUP = 20;

export async function run() {
  const fx = await createVault();
  try {
    const handle = await createBenchSecret(fx.engine, "bench-read", randomBytes(32));

    const ns = await measure(
      async () => {
        const value = await fx.engine.getSecretValue(handle);
        wipeBuffer(value);
      },
      { samples: SAMPLES, warmup: WARMUP },
    );
    const s = stats(ns);
    assertSane(
      s.medianMs < 10,
      `secret-read median ${s.medianMs} ms — expected sub-10 ms; miswired benchmark?`,
    );
    return {
      scenario: "secret-read",
      thesis: "(a) per-use_secret overhead: SQLite read + decrypt",
      metrics: { "VaultEngine.getSecretValue": s },
      notes: [
        "Timed: HMAC-SHA256 name lookup, SQLite row read, DEK unwrap, AES-256-GCM value decrypt, access audit write.",
        "The returned buffer is wiped after every sample, matching engine discipline.",
      ],
    };
  } finally {
    await fx.cleanup();
  }
}

if (isMain(import.meta)) {
  printScenario(await run());
}
