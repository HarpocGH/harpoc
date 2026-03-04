import type { Command } from "commander";

export function registerServerCommand(program: Command): void {
  program
    .command("server")
    .description("Start the harpoc server")
    .command("start")
    .description("Start MCP and/or REST server")
    .option("--mcp", "Start MCP server (stdio)")
    .option("--rest", "Start REST API server")
    .option("--port <port>", "REST API port", "3000")
    .action(() => {
      console.error("Error: Server commands are not yet implemented. Coming in Phase 7.");
      process.exit(1);
    });
}
