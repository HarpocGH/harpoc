import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "core",
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text-summary"],
    },
    testTimeout: 30_000,
    // Engine-building beforeEach fixtures sporadically blow the 10 s vitest
    // default on loaded CI runners — same ceiling as the tests themselves.
    hookTimeout: 30_000,
    // A dozen suites call initVault/unlock/changePassword with the real
    // Argon2id (2 GiB per derivation under the RFC 9106 profile); at the
    // default worker count the 7 GB macOS runners swap and marginal suites
    // blow even the 30 s ceiling. Two workers (4 GiB peak) still sat at the
    // paging edge there — run 31592644014 lost a single deriveKey to >30 s —
    // so darwin gets one. The 16 GB ubuntu/windows runners keep two.
    maxWorkers: process.platform === "darwin" ? 1 : 2,
    env: {
      // Keystore session wrapping stays off in tests: on Windows every engine
      // session write/read would otherwise spawn a PowerShell DPAPI helper.
      // The protector suites opt back in with explicit instances.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
