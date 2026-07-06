import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "core",
    testTimeout: 30_000,
    env: {
      // Keystore session wrapping stays off in tests: on Windows every engine
      // session write/read would otherwise spawn a PowerShell DPAPI helper.
      // The protector suites opt back in with explicit instances.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
