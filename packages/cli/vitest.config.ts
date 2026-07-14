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
    env: {
      // Keystore session wrapping off in tests — command handlers construct
      // engines internally and would spawn a DPAPI helper per session on Windows.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
