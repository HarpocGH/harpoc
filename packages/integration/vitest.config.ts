import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "integration",
    testTimeout: 60_000,
    hookTimeout: 30_000,
    env: {
      // Keystore session wrapping off in tests — the DPAPI path is exercised
      // explicitly by the Windows-gated session-sharing test.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
