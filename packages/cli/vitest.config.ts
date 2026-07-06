import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "cli",
    testTimeout: 30_000,
    env: {
      // Keystore session wrapping off in tests — command handlers construct
      // engines internally and would spawn a DPAPI helper per session on Windows.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
