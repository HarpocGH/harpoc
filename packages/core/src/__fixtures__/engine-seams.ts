import { ErrorCode, VaultError } from "@harpoc/shared";
import type { McpConnectionRegistry } from "../injection/mcp-registry.js";
import type { VaultEngine } from "../vault-engine.js";

/**
 * Register the agent identities a suite mints tokens or grants for — the v1.4
 * registration gate refuses an unregistered agent-typed principal. A name that
 * is already registered is accepted; any other refusal propagates.
 */
export function registerAgents(engine: VaultEngine, ...names: string[]): void {
  for (const name of names) {
    try {
      engine.registerAgent({ name });
    } catch (err) {
      if (!(err instanceof VaultError) || err.code !== ErrorCode.AGENT_EXISTS) throw err;
    }
  }
}

/** The engine's live MCP connection registry (test seam — private field). */
export function registryOf(engine: VaultEngine): McpConnectionRegistry {
  return (engine as unknown as { mcpRegistry: McpConnectionRegistry }).mcpRegistry;
}
