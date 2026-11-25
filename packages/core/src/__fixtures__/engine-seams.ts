import { AAD_INJECTION_POLICY, AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import { encrypt } from "../crypto/aes-gcm.js";
import type { McpConnectionEntry, McpConnectionRegistry } from "../injection/mcp-registry.js";
import type { RenderControl, RenderPlan, RenderRun } from "../injection/sftp-render.js";
import type { SecretManager } from "../secrets/secret-manager.js";
import type { SqliteStore } from "../storage/sqlite-store.js";
import type { SftpRenderSeam, VaultEngine } from "../vault-engine.js";

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
 * Publish a ready stdio entry into the engine's registry without spawning a
 * child: something live to tear down, closed through `close`.
 */
export async function seedLiveStdioEntry(
  engine: VaultEngine,
  secretId: string,
  close: () => Promise<unknown> = () => Promise.resolve(),
): Promise<void> {
  const client = { onclose: undefined, close };
  await registryOf(engine).acquire(secretId, () =>
    Promise.resolve({
      secretId,
      serverName: "docs",
      transportKind: "stdio",
      client: client as unknown as McpConnectionEntry["client"],
      state: "connecting",
      crashed: false,
      credentialFingerprint: "cred-fp",
      configFingerprint: "config-fp",
      isolation: { network: false, fs: false },
      strictTreeExit: false,
      spawnedAt: Date.now(),
      lastUsedAt: Date.now(),
    } satisfies McpConnectionEntry),
  );
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

/**
 * Store `blob` as a secret's injection policy past `setInjectionPolicy`, which
 * refuses some stored states a suite needs (test seam — private fields).
 */
export function storeInjectionPolicyBlob(
  engine: VaultEngine,
  secretId: string,
  blob: unknown,
): void {
  const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
  const enc = encrypt(
    kek,
    new Uint8Array(Buffer.from(JSON.stringify(blob), "utf8")),
    AAD_INJECTION_POLICY(secretId),
  );
  const now = Date.now();
  store.upsertInjectionPolicy({
    secret_id: secretId,
    policy_encrypted: enc.ciphertext,
    policy_iv: enc.iv,
    policy_tag: enc.tag,
    created_at: now,
    updated_at: now,
  });
}

/** What the render seam's stand-in answers where its script answers nothing: the file written, no child flag. */
export const RENDER_WRITTEN: RenderRun = {
  kind: "ran",
  outcome: { written: "yes" },
  spawn: { network_isolation: false, fs_isolation: false },
};

/**
 * Replace the engine's render seam (test seam — private field): the client's
 * version passes, `run` records each call's plan and control by reference and
 * answers what `script` answers, `RENDER_WRITTEN` where it answers nothing. A
 * script may wait on a promise its row settles; one that reads the content
 * copies it, since the engine zeroes it once the call has ended.
 */
export function installRenderSeam(
  engine: VaultEngine,
  script?: (plan: RenderPlan, control: RenderControl) => unknown,
  overrides: Partial<SftpRenderSeam> = {},
): { plan: RenderPlan; control: RenderControl }[] {
  const calls: { plan: RenderPlan; control: RenderControl }[] = [];
  (engine as unknown as { sftpRender: SftpRenderSeam }).sftpRender = {
    refuseOldClient: () => Promise.resolve(),
    run: async (plan, control) => {
      calls.push({ plan, control });
      const answer = await script?.(plan, control);
      return (answer ?? RENDER_WRITTEN) as RenderRun;
    },
    ...overrides,
  };
  return calls;
}

/**
 * The number of audit rows whose type is not `vault.read`, counted in the
 * engine's store rather than through `queryAudit` (test seam — private field).
 */
export function nonReadAuditCount(engine: VaultEngine): number {
  const { db } = (engine as unknown as { store: SqliteStore }).store;
  const row = db
    .prepare("SELECT COUNT(*) AS count FROM audit_log WHERE event_type != ?")
    .get(AuditEventType.VAULT_READ) as { count: number };
  return row.count;
}
