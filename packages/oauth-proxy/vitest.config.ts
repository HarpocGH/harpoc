import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "oauth-proxy",
    passWithNoTests: true,
  },
});
