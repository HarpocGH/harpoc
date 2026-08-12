import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "cli",
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
    // The e2e suites build real vaults (in-process and via the compiled
    // binary), each a real 2 GiB Argon2id derivation; parallel files put the
    // 7 GB macOS runners at the paging edge (run 31593548221: connect.e2e
    // hook past 30 s). Same shape as core/integration: darwin one worker,
    // the 16 GB runners two.
    maxWorkers: process.platform === "darwin" ? 1 : 2,
    env: {
      // Keystore session wrapping off in tests — command handlers construct
      // engines internally and would spawn a DPAPI helper per session on Windows.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
