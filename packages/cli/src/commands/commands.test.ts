import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuditEventType,
  ErrorCode,
  Permission,
  PrincipalType,
  SecretType,
  VaultError,
  VaultState,
} from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";
import type { SecretInfo, DecryptedAuditEvent } from "@harpoc/core";
import { resolveSecretId } from "../utils/vault-loader.js";

/**
 * These tests exercise VaultEngine directly — the same operations the CLI commands perform.
 * They validate the programmatic layer that every CLI command delegates to.
 */

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;
const TEST_PASSWORD = "test-password-123";

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-cli-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("init command flow", () => {
  it("creates a new vault", async () => {
    const { vaultId } = await engine.initVault(TEST_PASSWORD);
    expect(vaultId).toBeTruthy();
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
  });
});

describe("unlock/lock command flow", () => {
  it("unlocks and locks a vault", async () => {
    await engine.initVault(TEST_PASSWORD);
    await engine.lock();
    expect(engine.getState()).toBe(VaultState.SEALED);

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock(TEST_PASSWORD);
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
    await engine2.lock();
    expect(engine2.getState()).toBe(VaultState.SEALED);
    await engine2.destroy();
  });

  it("rejects wrong password", async () => {
    await engine.initVault(TEST_PASSWORD);
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    try {
      await engine2.unlock("wrong-password");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PASSWORD);
    }
    await engine2.destroy();
  });

  it("handles lockout after too many failed attempts", async () => {
    await engine.initVault(TEST_PASSWORD);
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      const eng = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong-pass");
      } catch {
        // Expected
      }
      await eng.destroy();
    }

    const eng = new VaultEngine({ dbPath, sessionPath });
    try {
      await eng.unlock("wrong-pass");
      expect.fail("Should throw lockout");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.LOCKOUT_ACTIVE);
    }
    await eng.destroy();
  });
});

describe("session loading flow", () => {
  it("loads session after init", async () => {
    await engine.initVault(TEST_PASSWORD);
    await engine.destroy();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
    await engine2.destroy();
  });

  it("returns false when no session exists", async () => {
    await engine.initVault(TEST_PASSWORD);
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(false);
    await engine2.destroy();
  });
});

describe("secret set/get/list command flow", () => {
  beforeEach(async () => {
    await engine.initVault(TEST_PASSWORD);
  });

  it("creates a secret with value", async () => {
    const result = await engine.createSecret({
      name: "my-api-key",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("sk-123456"),
    });
    expect(result.handle).toBe("secret://my-api-key");
    expect(result.status).toBe("created");
  });

  it("creates a secret in a project", async () => {
    const result = await engine.createSecret({
      name: "prod-key",
      type: SecretType.API_KEY,
      project: "myproject",
      value: new TextEncoder().encode("sk-prod"),
    });
    expect(result.handle).toBe("secret://myproject/prod-key");
  });

  it("retrieves secret info", async () => {
    await engine.createSecret({
      name: "info-test",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("test-value"),
    });

    const info: SecretInfo = await engine.getSecretInfo("secret://info-test");
    expect(info.name).toBe("info-test");
    expect(info.type).toBe(SecretType.API_KEY);
    expect(info.status).toBe("active");
    expect(info.version).toBe(1);
  });

  it("retrieves secret value", async () => {
    await engine.createSecret({
      name: "value-test",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("my-secret-value"),
    });

    const value = await engine.getSecretValue("secret://value-test");
    expect(new TextDecoder().decode(value)).toBe("my-secret-value");
  });

  it("lists secrets", async () => {
    await engine.createSecret({
      name: "list-a",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("a"),
    });
    await engine.createSecret({
      name: "list-b",
      type: SecretType.CERTIFICATE,
      project: "proj",
      value: new TextEncoder().encode("b"),
    });

    const all = engine.listSecrets();
    expect(all.length).toBe(2);

    const filtered = engine.listSecrets("proj");
    expect(filtered.length).toBe(1);
    const firstFiltered = filtered[0];
    expect(firstFiltered).toBeDefined();
    expect(firstFiltered?.name).toBe("list-b");
  });

  it("rejects duplicate secret names", async () => {
    await engine.createSecret({
      name: "dup-test",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("first"),
    });

    try {
      await engine.createSecret({
        name: "dup-test",
        type: SecretType.API_KEY,
        value: new TextEncoder().encode("second"),
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.DUPLICATE_SECRET);
    }
  });
});

describe("secret rotate command flow", () => {
  beforeEach(async () => {
    await engine.initVault(TEST_PASSWORD);
  });

  it("rotates a secret value", async () => {
    await engine.createSecret({
      name: "rotate-test",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("old-value"),
    });

    await engine.rotateSecret("secret://rotate-test", new TextEncoder().encode("new-value"));

    const value = await engine.getSecretValue("secret://rotate-test");
    expect(new TextDecoder().decode(value)).toBe("new-value");

    const info = await engine.getSecretInfo("secret://rotate-test");
    expect(info.version).toBe(2);
  });
});

describe("secret delete command flow", () => {
  beforeEach(async () => {
    await engine.initVault(TEST_PASSWORD);
  });

  it("revokes a secret", async () => {
    await engine.createSecret({
      name: "delete-test",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("val"),
    });

    await engine.revokeSecret("secret://delete-test");

    const info = await engine.getSecretInfo("secret://delete-test");
    expect(info.status).toBe("revoked");
  });
});

describe("audit command flow", () => {
  beforeEach(async () => {
    await engine.initVault(TEST_PASSWORD);
  });

  it("queries audit events", async () => {
    await engine.createSecret({
      name: "audit-test",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("val"),
    });

    const events: DecryptedAuditEvent[] = engine.queryAudit();
    // At least vault.unlock + secret.create
    expect(events.length).toBeGreaterThanOrEqual(2);

    const types = events.map((e) => e.event_type);
    expect(types).toContain(AuditEventType.VAULT_UNLOCK);
    expect(types).toContain(AuditEventType.SECRET_CREATE);
  });

  it("filters by event type", async () => {
    await engine.createSecret({
      name: "audit-filter",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("val"),
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(events.every((e) => e.event_type === AuditEventType.SECRET_CREATE)).toBe(true);
  });
});

describe("auth token command flow", () => {
  beforeEach(async () => {
    await engine.initVault(TEST_PASSWORD);
  });

  it("creates a scoped JWT token", () => {
    const token = engine.createToken("test-agent", [Permission.USE, Permission.LIST]);
    expect(token).toBeTruthy();
    expect(token.split(".").length).toBe(3);
  });

  it("verifies a valid token", () => {
    const token = engine.createToken("test-agent", [Permission.USE, Permission.LIST], 60000);
    const payload = engine.verifyToken(token);
    expect(payload.sub).toBe("test-agent");
    expect(payload.scope).toEqual([Permission.USE, Permission.LIST]);
  });

  it("creates token with agent subject", () => {
    const token = engine.createToken("my-bot", [Permission.USE], 3600000);
    const payload = engine.verifyToken(token);
    expect(payload.sub).toBe("my-bot");
  });

  it("revokes a token", () => {
    const token = engine.createToken("revoke-test", [Permission.USE]);
    const payload = engine.verifyToken(token);

    engine.revokeToken(payload.jti);

    try {
      engine.verifyToken(token);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.TOKEN_REVOKED);
    }
  });
});

describe("policy command flow", () => {
  beforeEach(async () => {
    await engine.initVault(TEST_PASSWORD);
  });

  it("grants, lists, and revokes a policy", async () => {
    const secret = await engine.createSecret({
      name: "policy-test",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("val"),
    });

    // Resolve the handle to get the internal secret UUID
    const secretId = await resolveSecretId(engine, secret.handle);

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: PrincipalType.AGENT,
        principalId: "claude-agent",
        permissions: [Permission.USE, Permission.LIST],
      },
      "cli-user",
    );
    expect(policy.id).toBeTruthy();
    expect(policy.principal_id).toBe("claude-agent");

    const policies = engine.listPolicies(secretId);
    expect(policies.length).toBeGreaterThanOrEqual(1);

    engine.revokePolicy(policy.id);
    const afterRevoke = engine.listPolicies(secretId);
    expect(afterRevoke.find((p) => p.id === policy.id)).toBeUndefined();
  });
});

describe("full lifecycle integration", () => {
  it("init → unlock → set → list → get → rotate → audit → lock", async () => {
    // 1. Init
    const { vaultId } = await engine.initVault(TEST_PASSWORD);
    expect(vaultId).toBeTruthy();

    // 2. Lock and re-unlock
    await engine.lock();
    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock(TEST_PASSWORD);

    // 3. Set secret
    const created = await engine2.createSecret({
      name: "integration-key",
      type: SecretType.API_KEY,
      value: new TextEncoder().encode("initial-value"),
    });
    expect(created.handle).toBe("secret://integration-key");

    // 4. List
    const list = engine2.listSecrets();
    expect(list.length).toBe(1);
    const firstSecret = list[0];
    expect(firstSecret).toBeDefined();
    expect(firstSecret?.name).toBe("integration-key");

    // 5. Get
    const info = await engine2.getSecretInfo("secret://integration-key");
    expect(info.status).toBe("active");
    const value = await engine2.getSecretValue("secret://integration-key");
    expect(new TextDecoder().decode(value)).toBe("initial-value");

    // 6. Rotate
    await engine2.rotateSecret(
      "secret://integration-key",
      new TextEncoder().encode("rotated-value"),
    );
    const rotatedVal = await engine2.getSecretValue("secret://integration-key");
    expect(new TextDecoder().decode(rotatedVal)).toBe("rotated-value");
    const rotatedInfo = await engine2.getSecretInfo("secret://integration-key");
    expect(rotatedInfo.version).toBe(2);

    // 7. Audit
    const events = engine2.queryAudit();
    expect(events.length).toBeGreaterThanOrEqual(4);
    const eventTypes = events.map((e) => e.event_type);
    expect(eventTypes).toContain(AuditEventType.VAULT_UNLOCK);
    expect(eventTypes).toContain(AuditEventType.SECRET_CREATE);
    expect(eventTypes).toContain(AuditEventType.SECRET_READ);
    expect(eventTypes).toContain(AuditEventType.SECRET_ROTATE);

    // 8. Lock
    await engine2.lock();
    expect(engine2.getState()).toBe(VaultState.SEALED);

    await engine2.destroy();
  });
});
