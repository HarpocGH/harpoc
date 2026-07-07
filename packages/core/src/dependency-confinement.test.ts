import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe } from "vitest";
import { describeRuntimeDependencyConfinement } from "../../shared/src/scaffold-helpers.js";

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * §5.2 dependency confinement, made true at runtime rather than only in
 * package.json: embedding core (the REST API does) must not load MCP SDK
 * code. The SDK enters the process exclusively through the lazy imports in
 * mcp-injector.ts / mcp-stdio-transport.ts, i.e. only when an MCP action
 * actually executes.
 */
describe("core", () => {
  describeRuntimeDependencyConfinement({
    entryUrl: pathToFileURL(resolve(pkgRoot, "dist", "index.js")).href,
    cwd: pkgRoot,
    forbidden: ["@modelcontextprotocol"],
    control: "@modelcontextprotocol/sdk/types.js",
  });
});
