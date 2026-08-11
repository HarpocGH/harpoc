// Scenario (b) — vault unlock latency (Argon2id, production parameters).
// Thesis: Ch. 6 §Baseline Performance. Times VaultEngine.unlock() only;
// the preceding lock() is untimed. Includes the KEK/JWT/audit-key unwrap and
// the session-file write (none-protector) — the real unlock path.

import { assertSane, isMain, measure, stats } from "./lib/harness.mjs";
import { printScenario } from "./lib/report.mjs";
import { createVault } from "./lib/vault-fixture.mjs";

const SAMPLES = 15;
const WARMUP = 2;

export async function run() {
  const fx = await createVault();
  try {
    const ns = await measure(() => fx.engine.unlock(fx.password), {
      samples: SAMPLES,
      warmup: WARMUP,
      beforeEach: () => fx.engine.lock(),
    });
    const s = stats(ns);
    // Floor recalibrated 2026-08-11 for the RFC 9106 high-security profile
    // (2 GiB/t=1/p=4, T-3 decision): ≈550 ms per derivation on the eval host.
    // A mocked or gutted KDF returns in single-digit ms — 100 ms catches that
    // failure mode with wide margin on any hardware that can run the profile.
    assertSane(
      s.medianMs > 100,
      `unlock median ${s.medianMs} ms is implausibly fast — production Argon2id (2 GiB, t=1, p=4) not exercised?`,
    );
    return {
      scenario: "unlock",
      thesis: "(b) vault unlock latency (Argon2id)",
      metrics: { "VaultEngine.unlock": s },
      notes: [
        "Timed: Argon2id derivation + AES-256-GCM KEK/JWT/audit-key unwrap + session write (none-protector) + unlock audit entry.",
        "Argon2id parameters are the production defaults (2 GiB, t=1, p=4 — RFC 9106 high-security profile) — no test mocks are active outside vitest.",
      ],
    };
  } finally {
    await fx.cleanup();
  }
}

if (isMain(import.meta)) {
  printScenario(await run());
}
