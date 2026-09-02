import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VaultEngine } from "@harpoc/core";
import {
  ErrorCode,
  VAULT_DB_NAME,
  SESSION_FILE_NAME,
  SecretType,
  VaultError,
} from "@harpoc/shared";
import type { Permission } from "@harpoc/shared";

export { EVIDENCE_FILE, PREREGISTRATION_FILE } from "../evidence/paths.js";

export interface HarnessVault {
  engine: VaultEngine;
  tmpDir: string;
  destroy(): Promise<void>;
}

export async function createHarnessVault(password: string): Promise<HarnessVault> {
  const tmpDir = mkdtempSync(join(tmpdir(), "harpoc-e2e-"));
  const engine = new VaultEngine({
    dbPath: join(tmpDir, VAULT_DB_NAME),
    sessionPath: join(tmpDir, SESSION_FILE_NAME),
  });
  await engine.initVault(password);

  return {
    engine,
    tmpDir,
    async destroy() {
      await engine.destroy();
      rmSync(tmpDir, { recursive: true, force: true });
    },
  };
}

/**
 * Register the principal a surface is about to mint a token for — the v1.4
 * registration gate refuses an unregistered agent-typed subject. Idempotent, so
 * several surfaces may share one principal name.
 */
export function ensureAgent(vault: HarnessVault, name: string): void {
  try {
    vault.engine.registerAgent({ name });
  } catch (err) {
    if (!(err instanceof VaultError) || err.code !== ErrorCode.AGENT_EXISTS) throw err;
  }
}

/**
 * Grant `permissions` on `handle` to the principal a surface mints its token
 * for. Under the explicit-grant model (R1, 2026-09-01) a token reaches a
 * secret only through a row, so every surface start pairs with a grant on the
 * handles it will drive. Trusted-path write; registers the agent first.
 */
export async function grantOn(
  vault: HarnessVault,
  handle: string,
  principal: string,
  permissions: Permission[],
): Promise<void> {
  ensureAgent(vault, principal);
  const secretId = await vault.engine.resolveSecretId(handle);
  vault.engine.grantPolicy(
    { secretId, principalType: "agent", principalId: principal, permissions },
    "e2e-harness",
  );
}

/** Store a credential and return its opaque handle. */
export async function storeSecret(
  vault: HarnessVault,
  name: string,
  value: string,
): Promise<string> {
  const created = await vault.engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new TextEncoder().encode(value),
  });
  return created.handle;
}
