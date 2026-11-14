import { builtinModules } from "node:module";
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  {
    ignores: ["**/dist/**", "**/node_modules/**", "**/*.js", "**/*.mjs"],
  },
  {
    files: ["packages/shared/src/**/*.ts"],
    ignores: ["packages/shared/src/**/*.test.ts", "packages/shared/src/**/__fixtures__/**"],
    rules: {
      "no-restricted-globals": [
        "error",
        "Buffer",
        "process",
        "__dirname",
        "__filename",
        "setImmediate",
        "global",
        "require",
      ],
      "no-restricted-imports": [
        "error",
        {
          paths: builtinModules.filter((name) => !name.startsWith("node:")),
          patterns: ["node:*"],
        },
      ],
      "no-restricted-properties": [
        "error",
        { object: "globalThis", property: "process" },
        { object: "globalThis", property: "Buffer" },
      ],
    },
  },
);
