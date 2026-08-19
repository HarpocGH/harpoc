/// <reference types="vitest/config" />
import preact from "@preact/preset-vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  base: "/ui/",
  plugins: [preact()],
  build: { outDir: "dist", emptyOutDir: true },
  // The vitest metadata lives here, not in a sibling vitest.config.ts: a
  // separate config file would override this one and drop the preact plugin.
  test: {
    name: "web-ui",
    environment: "jsdom",
    coverage: {
      include: ["src/**"],
      exclude: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    },
  },
});
