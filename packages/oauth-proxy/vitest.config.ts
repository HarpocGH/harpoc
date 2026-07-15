import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "oauth-proxy",
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text-summary"],
    },
    // Real-engine fixtures (initVault + loopback flows) routinely exceed the
    // 5 s default on loaded CI runners — same ceiling as core.
    testTimeout: 30_000,
    env: {
      // Keystore session wrapping off in tests (engine fixtures on Windows).
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
