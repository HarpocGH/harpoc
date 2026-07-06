import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "oauth-proxy",
    passWithNoTests: true,
    env: {
      // Keystore session wrapping off in tests (engine fixtures on Windows).
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
