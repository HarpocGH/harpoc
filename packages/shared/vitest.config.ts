import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "shared",
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text-summary"],
    },
  },
});
