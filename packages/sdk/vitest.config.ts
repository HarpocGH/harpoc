import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "sdk",
    // The first test to call startOAuthFlow/importCertificate pays the cold
    // dynamic import of a lazy optional peer (oauth-proxy / cert-manager)
    // while turbo runs every sibling suite in parallel — on a 2-core CI
    // runner that routinely exceeds vitest's default 5 s, which is why the
    // deferred-start test was the perennial CI timeout. 30 s matches the
    // core/cli/oauth-proxy/cert-manager convention.
    testTimeout: 30_000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text-summary"],
    },
  },
});
