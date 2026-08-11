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
    hookTimeout: 30_000,
    // Integration runs the real Argon2id (2 GiB per derivation under the
    // RFC 9106 high-security profile); unbounded parallel files exhaust host
    // memory. Two workers cap peak KDF memory at 4 GiB — within the 7 GB CI
    // runners.
    maxWorkers: 2,
    env: {
      // Keystore session wrapping off in tests — the DPAPI path is exercised
      // explicitly by the Windows-gated session-sharing test.
      HARPOC_SESSION_KEYSTORE: "off",
    },
  },
});
