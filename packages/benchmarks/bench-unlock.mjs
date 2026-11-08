// Scenario (b) — vault unlock latency (Argon2id, production parameters);
// (b′) the same unlock through the unlock key (deployment model B, M1 — no KDF).
// Thesis: Ch. 6 §Baseline Performance. Times VaultEngine.unlock() and
// VaultEngine.unlockWithKey() only; the preceding lock() is untimed. Both include
// the KEK/JWT/audit-key unwrap and the session-file write (none-protector) — the
// real unlock path.

import { assertSane, isMain, measure, stats } from "./lib/harness.mjs";
import { printScenario } from "./lib/report.mjs";
import { createVault, wipeBuffer } from "./lib/vault-fixture.mjs";

const SAMPLES = 15;
const WARMUP = 2;
// Measured 2026-11-08 on the eval host: ≈33 ms median, ≈19 ms of it the session
// write's icacls spawn (1.6 ms with no session write). A keystore round-trip on
// the key path lands near 200 ms (DPAPI) and a KDF near the password path's
// median, so 100 ms — the password path's floor — catches both on any host.
const KEY_PATH_CEILING_MS = 100;

export async function run() {
  const fx = await createVault();
  let key = null;
  try {
    const password = stats(
      await measure(() => fx.engine.unlock(fx.password), {
        samples: SAMPLES,
        warmup: WARMUP,
        beforeEach: () => fx.engine.lock(),
      }),
    );
    // Floor recalibrated 2026-08-11 for the RFC 9106 high-security profile
    // (2 GiB/t=1/p=4, T-3 decision): ≈550 ms per derivation on the eval host.
    // A mocked or gutted KDF returns in single-digit ms — 100 ms catches that
    // failure mode with wide margin on any hardware that can run the profile.
    assertSane(
      password.medianMs > 100,
      `unlock median ${password.medianMs} ms is implausibly fast — production Argon2id (2 GiB, t=1, p=4) not exercised?`,
    );

    // The last sample left the engine unlocked by the password, as the enrolment
    // requires; unlockWithKey wipes the buffer it is handed, so each sample gets
    // a copy, made untimed.
    key = await fx.engine.enrollUnlockKey();
    let copy = null;
    const unlockKey = stats(
      await measure(() => fx.engine.unlockWithKey(copy), {
        samples: SAMPLES,
        warmup: WARMUP,
        beforeEach: async () => {
          await fx.engine.lock();
          copy = new Uint8Array(key);
        },
      }),
    );
    assertSane(
      unlockKey.medianMs < KEY_PATH_CEILING_MS,
      `unlockWithKey median ${unlockKey.medianMs} ms is implausibly slow — a KDF or a keystore round-trip on the key path?`,
    );

    return {
      scenario: "unlock",
      thesis: "(b) vault unlock latency (Argon2id); (b′) unlock through the unlock key (no KDF)",
      metrics: {
        "VaultEngine.unlock": password,
        "(b′) VaultEngine.unlockWithKey (unlock key, no KDF)": unlockKey,
      },
      notes: [
        "Timed: Argon2id derivation + AES-256-GCM KEK/JWT/audit-key unwrap + session write (none-protector) + unlock audit entry.",
        "Argon2id parameters are the production defaults (2 GiB, t=1, p=4 — RFC 9106 high-security profile) — no test mocks are active outside vitest.",
        "(b′) Timed: AES-256-GCM unwrap of the KEK under the 32-byte unlock key (enrolled once with enrollUnlockKey(); no KDF on this path) + JWT/audit-key unwrap + session write (none-protector) + unlock audit entry (detail.method credential); the per-sample key copy and the preceding lock() are untimed.",
        "(b′) runs on the same file-mode engine as (b), so both figures carry the session write — on win32 its owner-only ACL is an icacls spawn — and the difference of their medians is the KDF; the B daemon runs --session memory and writes no session file.",
      ],
    };
  } finally {
    if (key !== null) wipeBuffer(key);
    await fx.cleanup();
  }
}

if (isMain(import.meta)) {
  printScenario(await run());
}
