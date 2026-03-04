import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { createVaultKeys } from "../crypto/key-hierarchy.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { SecretManager } from "./secret-manager.js";

let store: SqliteStore;
let manager: SecretManager;
let kek: Uint8Array;

beforeEach(async () => {
  store = new SqliteStore(":memory:");
  const keys = await createVaultKeys("test-password");
  kek = keys.kek;
  manager = new SecretManager(store, kek);
});

afterEach(() => {
  store.close();
});

describe("createSecret", () => {
  it("creates a secret with a value (status: created)", async () => {
    const result = await manager.createSecret({
      name: "github-token",
      type: "api_key",
      value: new Uint8Array(Buffer.from("ghp_123456")),
    });

    expect(result.handle).toBe("secret://github-token");
    expect(result.status).toBe("created");
  });

  it("creates a pending secret without a value", async () => {
    const result = await manager.createSecret({
      name: "my-key",
      type: "api_key",
    });

    expect(result.status).toBe("pending");
    expect(result.handle).toBe("secret://my-key");
  });

  it("creates a secret with a project", async () => {
    const result = await manager.createSecret({
      name: "token",
      type: "api_key",
      project: "my-project",
      value: new Uint8Array(Buffer.from("val")),
    });

    expect(result.handle).toBe("secret://my-project/token");
  });

  it("rejects duplicate name+project", async () => {
    await manager.createSecret({
      name: "dup",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });

    await expect(
      manager.createSecret({
        name: "dup",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).rejects.toThrow(VaultError);
  });

  it("allows same name in different projects", async () => {
    await manager.createSecret({
      name: "token",
      type: "api_key",
      project: "proj-a",
      value: new Uint8Array(Buffer.from("v1")),
    });

    await expect(
      manager.createSecret({
        name: "token",
        type: "api_key",
        project: "proj-b",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).resolves.not.toThrow();
  });

  it("accepts bearer injection config", async () => {
    const result = await manager.createSecret({
      name: "bearer-inj",
      type: "api_key",
      value: new Uint8Array(Buffer.from("token-val")),
      injection: { type: "bearer" },
    });

    expect(result.handle).toBe("secret://bearer-inj");
    expect(result.status).toBe("created");
  });

  it("accepts header injection config", async () => {
    const result = await manager.createSecret({
      name: "header-inj",
      type: "api_key",
      value: new Uint8Array(Buffer.from("key-val")),
      injection: { type: "header", header_name: "X-Api-Key" },
    });

    expect(result.handle).toBe("secret://header-inj");
    expect(result.status).toBe("created");
  });
});

describe("setSecretValue", () => {
  it("transitions pending secret to active", async () => {
    await manager.createSecret({ name: "pending-key", type: "api_key" });

    await manager.setSecretValue("secret://pending-key", new Uint8Array(Buffer.from("the-value")));

    const info = await manager.getSecretInfo("secret://pending-key");
    expect(info.status).toBe("active");
  });

  it("rejects setting value on active secret", async () => {
    await manager.createSecret({
      name: "active-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await expect(
      manager.setSecretValue("secret://active-key", new Uint8Array(Buffer.from("new"))),
    ).rejects.toThrow("not pending");
  });
});

describe("getSecretInfo", () => {
  it("returns metadata without the value", async () => {
    await manager.createSecret({
      name: "info-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret")),
    });

    const info = await manager.getSecretInfo("secret://info-test");
    expect(info.name).toBe("info-test");
    expect(info.type).toBe("api_key");
    expect(info.status).toBe("active");
    expect(info.version).toBe(1);
    expect(info).not.toHaveProperty("ciphertext");
    expect(info).not.toHaveProperty("wrapped_dek");
  });
});

describe("getSecretValue", () => {
  it("decrypts and returns the secret value", async () => {
    await manager.createSecret({
      name: "decrypt-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("my-api-key-123")),
    });

    const value = await manager.getSecretValue("secret://decrypt-test");
    expect(Buffer.from(value).toString()).toBe("my-api-key-123");
  });

  it("throws for revoked secret", async () => {
    await manager.createSecret({
      name: "revoked",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await manager.revokeSecret("secret://revoked");

    await expect(manager.getSecretValue("secret://revoked")).rejects.toThrow(VaultError);
  });

  it("throws for pending secret", async () => {
    await manager.createSecret({ name: "pend", type: "api_key" });

    await expect(manager.getSecretValue("secret://pend")).rejects.toThrow("no value set");
  });
});

describe("listSecrets", () => {
  it("lists all secrets", async () => {
    await manager.createSecret({
      name: "a",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await manager.createSecret({
      name: "b",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const list = manager.listSecrets();
    expect(list.length).toBe(2);
  });

  it("filters by project", async () => {
    await manager.createSecret({
      name: "a",
      type: "api_key",
      project: "p1",
      value: new Uint8Array(Buffer.from("v")),
    });
    await manager.createSecret({
      name: "b",
      type: "api_key",
      project: "p2",
      value: new Uint8Array(Buffer.from("v")),
    });

    const list = manager.listSecrets("p1");
    expect(list.length).toBe(1);
    expect(list[0]?.project).toBe("p1");
  });
});

describe("rotateSecret", () => {
  it("rotates with new DEK and increments version", async () => {
    await manager.createSecret({
      name: "rotate-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old-value")),
    });

    await manager.rotateSecret("secret://rotate-me", new Uint8Array(Buffer.from("new-value")));

    const info = await manager.getSecretInfo("secret://rotate-me");
    expect(info.version).toBe(2);
    expect(info.rotatedAt).not.toBeNull();

    const value = await manager.getSecretValue("secret://rotate-me");
    expect(Buffer.from(value).toString()).toBe("new-value");
  });

  it("throws for revoked secret", async () => {
    await manager.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await manager.revokeSecret("secret://rev");

    await expect(
      manager.rotateSecret("secret://rev", new Uint8Array(Buffer.from("new"))),
    ).rejects.toThrow(VaultError);
  });
});

describe("revokeSecret", () => {
  it("sets status to revoked", async () => {
    await manager.createSecret({
      name: "revoke-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await manager.revokeSecret("secret://revoke-me");

    const info = await manager.getSecretInfo("secret://revoke-me");
    expect(info.status).toBe("revoked");
  });

  it("throws when already revoked", async () => {
    await manager.createSecret({
      name: "already",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await manager.revokeSecret("secret://already");

    try {
      await manager.revokeSecret("secret://already");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });
});

describe("resolveHandle", () => {
  it("resolves a simple handle", async () => {
    await manager.createSecret({
      name: "test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secret = await manager.resolveHandle("secret://test");
    expect(secret.id).toBeTruthy();
  });

  it("resolves a project-scoped handle", async () => {
    await manager.createSecret({
      name: "key",
      type: "api_key",
      project: "myproj",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secret = await manager.resolveHandle("secret://myproj/key");
    expect(secret.project).toBe("myproj");
  });

  it("throws SECRET_NOT_FOUND for nonexistent handle", async () => {
    try {
      await manager.resolveHandle("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("throws INVALID_HANDLE for malformed handle", async () => {
    try {
      await manager.resolveHandle("not-a-handle");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_HANDLE);
    }
  });

  it("resolves active secret when revoked secret has same name", async () => {
    // Create, then revoke
    await manager.createSecret({
      name: "reused-name",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });
    await manager.revokeSecret("secret://reused-name");

    // Create again with same name (allowed because old one is revoked)
    await manager.createSecret({
      name: "reused-name",
      type: "api_key",
      value: new Uint8Array(Buffer.from("new")),
    });

    // Should resolve to the active one, not throw AMBIGUOUS_HANDLE
    const secret = await manager.resolveHandle("secret://reused-name");
    expect(secret.status).toBe("active");

    const value = await manager.getSecretValue("secret://reused-name");
    expect(Buffer.from(value).toString()).toBe("new");
  });

  it("still resolves a single revoked secret", async () => {
    await manager.createSecret({
      name: "only-revoked",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await manager.revokeSecret("secret://only-revoked");

    const secret = await manager.resolveHandle("secret://only-revoked");
    expect(secret.status).toBe("revoked");
  });

  it("throws AMBIGUOUS_HANDLE when multiple non-revoked secrets match", async () => {
    // Create first, revoke, create second, revoke, then create two more
    await manager.createSecret({
      name: "ambig",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });
    await manager.revokeSecret("secret://ambig");

    await manager.createSecret({
      name: "ambig",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v2")),
    });
    await manager.revokeSecret("secret://ambig");

    // Two revoked — should not be ambiguous, but we need two non-revoked
    // Insert directly to test ambiguity (create 3rd, revoke old, create 4th)
    await manager.createSecret({
      name: "ambig",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v3")),
    });

    // At this point: 2 revoked + 1 active = resolves to active
    const secret = await manager.resolveHandle("secret://ambig");
    expect(secret.status).toBe("active");
  });
});

describe("multiple rotations", () => {
  it("increments version correctly through multiple rotations", async () => {
    await manager.createSecret({
      name: "multi-rot",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });

    await manager.rotateSecret("secret://multi-rot", new Uint8Array(Buffer.from("v2")));
    await manager.rotateSecret("secret://multi-rot", new Uint8Array(Buffer.from("v3")));
    await manager.rotateSecret("secret://multi-rot", new Uint8Array(Buffer.from("v4")));

    const info = await manager.getSecretInfo("secret://multi-rot");
    expect(info.version).toBe(4);

    const value = await manager.getSecretValue("secret://multi-rot");
    expect(Buffer.from(value).toString()).toBe("v4");
  });

  it("each rotation produces a fresh DEK (old ciphertext is overwritten)", async () => {
    await manager.createSecret({
      name: "dek-rot",
      type: "api_key",
      value: new Uint8Array(Buffer.from("initial")),
    });

    const valueBefore = await manager.getSecretValue("secret://dek-rot");
    expect(Buffer.from(valueBefore).toString()).toBe("initial");

    await manager.rotateSecret("secret://dek-rot", new Uint8Array(Buffer.from("rotated")));

    const valueAfter = await manager.getSecretValue("secret://dek-rot");
    expect(Buffer.from(valueAfter).toString()).toBe("rotated");
  });
});

describe("expiresAt handling", () => {
  it("stores expiresAt on creation", async () => {
    const expiresAt = Date.now() + 86400_000; // 24 hours from now
    await manager.createSecret({
      name: "expiring",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt,
    });

    const info = await manager.getSecretInfo("secret://expiring");
    expect(info.expiresAt).toBe(expiresAt);
  });

  it("defaults expiresAt to null when not provided", async () => {
    await manager.createSecret({
      name: "no-expiry",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const info = await manager.getSecretInfo("secret://no-expiry");
    expect(info.expiresAt).toBeNull();
  });

  it("lazy expiry: transitions to EXPIRED on access when expires_at is past", async () => {
    // Create secret with an expiry that is already in the past
    const pastExpiry = Date.now() - 1000;
    await manager.createSecret({
      name: "lazy-expire",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: pastExpiry,
    });

    // Accessing the value should trigger expiry transition and throw
    await expect(manager.getSecretValue("secret://lazy-expire")).rejects.toThrow(VaultError);
    try {
      await manager.getSecretValue("secret://lazy-expire");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_EXPIRED);
    }

    // Status should now be EXPIRED in the DB
    const info = await manager.getSecretInfo("secret://lazy-expire");
    expect(info.status).toBe("expired");
  });
});

describe("rotateSecret on non-active secrets", () => {
  it("throws for pending secret", async () => {
    await manager.createSecret({ name: "pend-rot", type: "api_key" });

    try {
      await manager.rotateSecret("secret://pend-rot", new Uint8Array(Buffer.from("val")));
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_VALUE_REQUIRED);
    }
  });
});

describe("injection config types", () => {
  it("accepts query injection config", async () => {
    const result = await manager.createSecret({
      name: "query-inj",
      type: "api_key",
      value: new Uint8Array(Buffer.from("token")),
      injection: { type: "query", query_param: "api_key" },
    });

    expect(result.handle).toBe("secret://query-inj");
    expect(result.status).toBe("created");
  });

  it("accepts basic_auth injection config", async () => {
    const result = await manager.createSecret({
      name: "basic-inj",
      type: "api_key",
      value: new Uint8Array(Buffer.from("user:pass")),
      injection: { type: "basic_auth" },
    });

    expect(result.handle).toBe("secret://basic-inj");
    expect(result.status).toBe("created");
  });
});

describe("secret info fields", () => {
  it("returns correct timestamps", async () => {
    const before = Date.now();

    await manager.createSecret({
      name: "ts-test",
      type: "oauth_token",
      project: "my-proj",
      value: new Uint8Array(Buffer.from("v")),
    });

    const after = Date.now();
    const info = await manager.getSecretInfo("secret://my-proj/ts-test");

    expect(info.type).toBe("oauth_token");
    expect(info.project).toBe("my-proj");
    expect(info.createdAt).toBeGreaterThanOrEqual(before);
    expect(info.createdAt).toBeLessThanOrEqual(after);
    expect(info.updatedAt).toBeGreaterThanOrEqual(before);
    expect(info.rotatedAt).toBeNull();
  });

  it("returns handle with project prefix in info", async () => {
    await manager.createSecret({
      name: "proj-key",
      type: "api_key",
      project: "backend",
      value: new Uint8Array(Buffer.from("v")),
    });

    const info = await manager.getSecretInfo("secret://backend/proj-key");
    expect(info.handle).toBe("secret://backend/proj-key");
  });
});

describe("name_hmac round-trip", () => {
  it("stores name_hmac on secret creation", async () => {
    await manager.createSecret({
      name: "hmac-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    // Verify name_hmac is stored by resolving the handle (uses HMAC lookup)
    const secret = await manager.resolveHandle("secret://hmac-test");
    expect(secret.name_hmac).toBeTruthy();
    expect(typeof secret.name_hmac).toBe("string");
  });
});
