import { ErrorCode, VaultError } from "@harpoc/shared";
import type { McpConnectionRegistry } from "../injection/mcp-registry.js";
import type { SecretManager } from "../secrets/secret-manager.js";
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

/**
 * Keep every plaintext the engine's live secret manager decrypts — the very
 * `Uint8Array` `getSecretValue` hands the engine, by reference, never a copy —
 * so a test can observe the engine's own wipe of it (C5). The manager is
 * rebuilt on every unlock and session load: install after the last of them.
 */
export function retainDecryptedValues(engine: VaultEngine): Uint8Array[] {
  const manager = (engine as unknown as { secretManager: SecretManager }).secretManager;
  const decrypt = manager.getSecretValue.bind(manager);
  const retained: Uint8Array[] = [];
  manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
    const value = await decrypt(...args);
    retained.push(value);
    return value;
  };
  return retained;
}
