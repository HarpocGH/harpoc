// The package's library entry (`exports["."]`): `index.ts` is the `harpoc-mcp`
// binary only, so `harpoc-mcp --url` loads none of the engine modules these
// re-exports pull in (B1).
export { createMcpServer, createStdioServerFactory } from "./server.js";
export type { CreateMcpServerOptions } from "./server.js";
export { startMcpHttpServer, DEFAULT_MCP_HTTP_PORT } from "./http.js";
export type { McpHttpServer, McpHttpServerOptions } from "./http.js";
export { RateLimiter } from "./guards/rate-limiter.js";
export { ScopeGuard } from "./guards/scope-guard.js";
export { InjectionGuard } from "./guards/injection-guard.js";
export {
  parseAllowedHostsOption,
  readLaunchTokenFile,
  MAX_LAUNCH_TOKEN_FILE_BYTES,
} from "./cli-options.js";
export type { AllowedHostsParse, TokenFileRead } from "./cli-options.js";
