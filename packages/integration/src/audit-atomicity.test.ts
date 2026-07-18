import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const PASSWORD = "integration-password";

let vault: TestVault;

beforeEach(async () => {
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
});

afterEach(async () => {
  await destroyTestVault(vault);
});

// NM3 composition proof: every audited mutation now commits inside one SQLite
// transaction with its audit row(s). A mixed lifecycle across the real
// database file must leave a linear, anchorable HMAC chain with every detail
// blob still row-bound decryptable.

describe("transactional audit writes across a real lifecycle", () => {
  it("keeps the chain verifiable through mixed transactional and single-insert writes", async () => {
    await vault.engine.createSecret({
      name: "life-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });
    await vault.engine.setInjectionPolicy(
      "secret://life-key",
      { command_allowlist: [process.execPath] },
      { acknowledge_interpreters: true },
    );
    await vault.engine.rotateSecret("secret://life-key", new Uint8Array(Buffer.from("v2")));
    await expect(vault.engine.getSecretValue("secret://missing")).rejects.toThrow();
    const token = vault.engine.createToken("agent-1", ["read"]);
    vault.engine.revokeToken(vault.engine.verifyToken(token).jti);
    await vault.engine.revokeSecret("secret://life-key");
    await vault.engine.changePassword(PASSWORD, "rotated-password-1");

    const report = vault.engine.verifyAuditChain();
    expect(report.valid).toBe(true);

    const anchor = vault.engine.getAuditChainTail();
    expect(anchor).not.toBeNull();
    expect(
      vault.engine.verifyAuditChain({ anchor: anchor as NonNullable<typeof anchor> }).valid,
    ).toBe(true);

    // The multi-row transaction (grant + interpreter ack) landed both rows.
    expect(
      vault.engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED }),
    ).toHaveLength(1);

    // Every detail blob still decrypts under its row-bound AAD.
    expect(vault.engine.queryAudit().filter((e) => e.detail_unreadable)).toHaveLength(0);

    // The password change committed as one generation: a fresh engine unlocks
    // with the new password against the same database file.
    await vault.engine.destroy();
    vault.engine = createTestVault(vault.tmpDir).engine;
    await vault.engine.unlock("rotated-password-1");
    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });
});
