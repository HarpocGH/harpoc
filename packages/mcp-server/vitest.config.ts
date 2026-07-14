import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "mcp-server",
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text-summary"],
    },
  },
});
