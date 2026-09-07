import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "integration",
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text-summary"],
    },
    testTimeout: 60_000,
    // The hook bound follows the test bound: a `beforeAll` runs the same
    // Argon2id init a test does, and the windows-latest / Node 24 leg of run
    // 34128203607 (2026-09-07) timed one out at 30 s under a load spike while
    // the sibling Windows leg ran the whole file in 3.5 s.
    hookTimeout: 60_000,
    // Integration runs the real Argon2id (2 GiB per derivation under the
    // RFC 9106 high-security profile); unbounded parallel files exhaust host
    // memory. Two workers (4 GiB peak) still sat at the paging edge on the
    // 7 GB macOS runners (run 31592644014: two 30 s hook timeouts), so darwin
    // gets one. The 16 GB ubuntu/windows runners keep two.
    maxWorkers: process.platform === "darwin" ? 1 : 2,
    env: {
      // Keystore session wrapping off in tests — the DPAPI path is exercised
      // explicitly by the Windows-gated session-sharing test.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
