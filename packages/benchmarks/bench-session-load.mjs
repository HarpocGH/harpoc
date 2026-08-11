// Scenario (d) — session-load overhead: DPAPI-wrapped vs. unwrapped session key.
// Thesis: Ch. 5 § Session File cites ≈150 ms per session load on the eval host;
// this script is the reproducible artifact behind that figure. Windows-only —
// elsewhere it skips (§4.6 file-permission fallback, no keystore implemented).
// Optional --cli: additionally wall-clocks a full CLI command per variant,
// reproducing the ≈650 vs ≈490 ms end-to-end figures from decisions.md (d2).

import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { REPO_DIR } from "./lib/env-info.mjs";
import { assertSane, isMain, measure, stats } from "./lib/harness.mjs";
import { printScenario } from "./lib/report.mjs";
import {
  DpapiSessionKeyProtector,
  NoneSessionKeyProtector,
  SessionManager,
  createVault,
} from "./lib/vault-fixture.mjs";

const SAMPLES = 50;
const WARMUP = 5;
const CLI_SAMPLES = 20;
const CLI_WARMUP = 3;
const CLI_ENTRY = join(REPO_DIR, "packages", "cli", "dist", "index.js");

const CLAIMED_DELTA_MS = 150; // Ch. 5 § Session File
const TOLERANCE = 0.5;

function runCliOnce(vaultDir, env) {
  const res = spawnSync(
    process.execPath,
    [CLI_ENTRY, "secret", "list", "--json", "--vault-dir", vaultDir],
    {
      env,
      encoding: "utf8",
      windowsHide: true,
    },
  );
  if (res.status !== 0) {
    throw new Error(`CLI exited ${res.status}: ${(res.stderr || res.stdout || "").slice(0, 400)}`);
  }
}

export async function run({ cli = false } = {}) {
  if (process.platform !== "win32") {
    return {
      scenario: "session-load",
      thesis: "(d) session-load overhead: DPAPI vs. none",
      skipped: true,
      reason: "DPAPI is Windows-only; the §4.6 file-permission fallback applies on this platform.",
    };
  }

  const variants = [
    {
      name: "none",
      makeProtector: () => new NoneSessionKeyProtector(),
      cliEnv: { HARPOC_SESSION_KEYSTORE: "off" },
    },
    { name: "dpapi", makeProtector: () => new DpapiSessionKeyProtector(), cliEnv: {} },
  ];

  const metrics = {};
  const notes = [];

  for (const variant of variants) {
    const fx = await createVault({ protector: variant.makeProtector() });
    try {
      const reader = new SessionManager(fx.sessionPath, { protector: variant.makeProtector() });
      const probe = await reader.readSession();
      assertSane(probe !== null, `${variant.name}: readSession() returned null on a fresh session`);

      const ns = await measure(
        async () => {
          const session = await reader.readSession();
          if (session === null)
            throw new Error(`${variant.name}: readSession() null mid-benchmark`);
        },
        { samples: SAMPLES, warmup: WARMUP },
      );
      metrics[`SessionManager.readSession (${variant.name})`] = stats(ns);

      if (cli) {
        const env = { ...process.env, ...variant.cliEnv };
        if (variant.name === "dpapi") delete env.HARPOC_SESSION_KEYSTORE;
        const cliNs = await measure(() => runCliOnce(fx.dir, env), {
          samples: CLI_SAMPLES,
          warmup: CLI_WARMUP,
        });
        metrics[`CLI secret list (${variant.name})`] = stats(cliNs);
      }
    } finally {
      await fx.cleanup();
    }
  }

  const deltaMs =
    Math.round(
      (metrics["SessionManager.readSession (dpapi)"].medianMs -
        metrics["SessionManager.readSession (none)"].medianMs) *
        1000,
    ) / 1000;
  notes.push(
    `DPAPI overhead (median delta): ${deltaMs} ms per session load — the PowerShell-host unprotect round-trip.`,
  );

  const lo = CLAIMED_DELTA_MS * (1 - TOLERANCE);
  const hi = CLAIMED_DELTA_MS * (1 + TOLERANCE);
  if (deltaMs < lo || deltaMs > hi) {
    notes.push(
      `⚠ measured delta departs from the Ch. 5 §Session File claim of ≈${CLAIMED_DELTA_MS} ms by more than ±${TOLERANCE * 100}% — update the thesis figure to the measured value.`,
    );
  } else {
    notes.push(
      `Consistent with the Ch. 5 §Session File claim of ≈${CLAIMED_DELTA_MS} ms (tolerance ±${TOLERANCE * 100}%).`,
    );
  }
  if (cli) {
    notes.push(
      "CLI rows wall-clock a full `secret list --json` (Node startup + engine init + session load), reproducing the decisions.md end-to-end figures.",
    );
  }

  return {
    scenario: "session-load",
    thesis: "(d) session-load overhead: DPAPI vs. none",
    metrics,
    notes,
  };
}

if (isMain(import.meta)) {
  printScenario(await run({ cli: process.argv.includes("--cli") }));
}
