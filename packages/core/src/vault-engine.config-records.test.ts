import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, callerFromToken, ErrorCode } from "@harpoc/shared";
import { AAD_CONNECTION_CONFIG, AAD_MCP_SERVER_CONFIG } from "@harpoc/shared";
import type { CallerContext, Permission, TokenPrincipalType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";
import { decrypt, encrypt } from "./crypto/aes-gcm.js";
import { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

function callerFor(
  subject: string,
  scope: Permission[],
  principalType: TokenPrincipalType,
): CallerContext {
  const jwt = engine.createToken(subject, scope, 60_000, { principalType });
  return callerFromToken(engine.verifyToken(jwt), "rest");
}

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("MCP server config", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "mcp",
      type: "api_key",
      value: new Uint8Array(Buffer.from("mcpsecret")),
    });
  });

  it("round-trips a stdio config", async () => {
    await engine.setMcpServerConfig("secret://mcp", {
      server_name: "github-mcp",
      transport: "stdio",
      protocol: "2025-11-25",
      command: process.execPath,
      args: ["server.js"],
      env_var: "GITHUB_TOKEN",
    });
    const config = await engine.getMcpServerConfig("secret://mcp");
    expect(config?.server_name).toBe("github-mcp");
    expect(config?.transport).toBe("stdio");
    expect(config?.command).toBe(process.execPath);
    expect(config?.env_var).toBe("GITHUB_TOKEN");
  });

  it("returns undefined when no config is set", async () => {
    expect(await engine.getMcpServerConfig("secret://mcp")).toBeUndefined();
  });

  it("audits a config change as POLICY_GRANT with policy=mcp_server", async () => {
    await engine.setMcpServerConfig("secret://mcp", {
      server_name: "github-mcp",
      transport: "http",
      protocol: "2025-11-25",
      url: "https://mcp.example.com/mcp",
    });
    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
    const grant = events.find((e) => e.detail?.policy === "mcp_server");
    expect(grant?.detail?.server_name).toBe("github-mcp");
    expect(grant?.detail?.transport).toBe("http");
  });

  it("deletes a config and audits POLICY_REVOKE", async () => {
    await engine.setMcpServerConfig("secret://mcp", {
      server_name: "github-mcp",
      transport: "http",
      protocol: "2025-11-25",
      url: "https://mcp.example.com/mcp",
    });
    expect(await engine.deleteMcpServerConfig("secret://mcp")).toBe(true);
    expect(await engine.getMcpServerConfig("secret://mcp")).toBeUndefined();
    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      success: true,
      secret_id: await engine.resolveSecretId("secret://mcp"),
      principal_type: null,
    });
    expect(events[0]?.detail).toEqual({ policy: "mcp_server" });
  });

  it("returns false when deleting a nonexistent config", async () => {
    expect(await engine.deleteMcpServerConfig("secret://mcp")).toBe(false);
  });

  const writeStoredMcpConfig = async (handle: string, plaintext: string): Promise<void> => {
    const secretId = await engine.resolveSecretId(handle);
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(plaintext, "utf8")),
      AAD_MCP_SERVER_CONFIG(secretId),
    );
    const now = Date.now();
    store.upsertMcpServer({
      secret_id: secretId,
      config_encrypted: enc.ciphertext,
      config_iv: enc.iv,
      config_tag: enc.tag,
      created_at: now,
      updated_at: now,
    });
  };

  const rewriteStoredMcpConfig = async (
    handle: string,
    transform: (config: Record<string, unknown>) => Record<string, unknown>,
  ): Promise<void> => {
    const secretId = await engine.resolveSecretId(handle);
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const row = store.getMcpServer(secretId);
    if (!row) throw new Error("no stored MCP server config");
    const plaintext = decrypt(
      kek,
      row.config_encrypted,
      row.config_iv,
      row.config_tag,
      AAD_MCP_SERVER_CONFIG(secretId),
    );
    const rewritten = transform(
      JSON.parse(Buffer.from(plaintext).toString("utf8")) as Record<string, unknown>,
    );
    await writeStoredMcpConfig(handle, JSON.stringify(rewritten));
  };

  it("a config stored before the protocol field reads back with the default (the one read-side default)", async () => {
    await engine.setMcpServerConfig("secret://mcp", {
      server_name: "s",
      transport: "http",
      url: "https://x.example/mcp",
      protocol: "2025-11-25",
    });
    // Simulate the pre-field blob: rewrite the stored JSON without `protocol`.
    await rewriteStoredMcpConfig("secret://mcp", (config) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { protocol: _dropped, ...rest } = config;
      return rest;
    });
    const read = await engine.getMcpServerConfig("secret://mcp");
    expect(read?.protocol).toBe("2025-11-25");
  });

  it("a malformed stored config is VAULT_CORRUPTED, never a silent default", async () => {
    await engine.setMcpServerConfig("secret://mcp", {
      server_name: "s",
      transport: "http",
      url: "https://x.example/mcp",
      protocol: "2025-11-25",
    });
    await rewriteStoredMcpConfig("secret://mcp", (c) => ({ ...c, transport: "sse" }));
    const err = await expectVaultError(
      () => engine.getMcpServerConfig("secret://mcp"),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(err.message).toContain("is malformed");
    expect(err.message).toContain("transport");
    expect(err.message).not.toContain("sse");
  });

  it("a stored config that is not JSON is VAULT_CORRUPTED, never a raw SyntaxError", async () => {
    await engine.setMcpServerConfig("secret://mcp", {
      server_name: "s",
      transport: "http",
      url: "https://x.example/mcp",
      protocol: "2025-11-25",
    });
    await writeStoredMcpConfig("secret://mcp", "not json");
    const err = await expectVaultError(
      () => engine.getMcpServerConfig("secret://mcp"),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(err.message).toContain("is not JSON");
    expect(err.message).not.toContain("not json");
  });

  it("refuses an MCP server config with an extra key before writing, naming the path (P3-11)", async () => {
    await expect(
      engine.setMcpServerConfig("secret://mcp", {
        server_name: "srv",
        transport: "http",
        url: "https://mcp.example.com/mcp",
        stray: 1,
      } as never),
    ).rejects.toMatchObject({
      code: ErrorCode.SCHEMA_VALIDATION_ERROR,
      message: expect.stringContaining(
        'Invalid MCP server config: <root>: Unrecognized key: "stray"',
      ),
    });
    expect(await engine.getMcpServerConfig("secret://mcp")).toBeUndefined();
  });
});

describe("connection config", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "conn",
      type: "api_key",
      value: new Uint8Array(Buffer.from("connsecret")),
    });
  });

  it("round-trips a database + ssh config", async () => {
    await engine.setConnectionConfig("secret://conn", {
      database: { tls_mode: "require", servername: "db.example.com" },
      ssh: { known_hosts: ["db.example.com ssh-ed25519 AAAA..."] },
    });
    const config = await engine.getConnectionConfig("secret://conn");
    expect(config?.database?.tls_mode).toBe("require");
    expect(config?.database?.servername).toBe("db.example.com");
    expect(config?.ssh?.known_hosts).toEqual(["db.example.com ssh-ed25519 AAAA..."]);
  });

  it("returns undefined when no config is set", async () => {
    expect(await engine.getConnectionConfig("secret://conn")).toBeUndefined();
  });

  it("audits a config change as POLICY_GRANT with policy=connection", async () => {
    await engine.setConnectionConfig("secret://conn", {
      database: { tls_mode: "disable" },
    });
    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
    const grant = events.find((e) => e.detail?.policy === "connection");
    expect(grant?.detail?.has_database).toBe(true);
    expect(grant?.detail?.database_tls).toBe("disable");
  });

  it("deletes a config and audits POLICY_REVOKE", async () => {
    await engine.setConnectionConfig("secret://conn", {
      ssh: { known_hosts: ["h ssh-ed25519 AAAA..."] },
    });
    expect(await engine.deleteConnectionConfig("secret://conn")).toBe(true);
    expect(await engine.getConnectionConfig("secret://conn")).toBeUndefined();
    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      success: true,
      secret_id: await engine.resolveSecretId("secret://conn"),
      principal_type: null,
    });
    expect(events[0]?.detail).toEqual({ policy: "connection" });
  });

  it("returns false when deleting a nonexistent config", async () => {
    expect(await engine.deleteConnectionConfig("secret://conn")).toBe(false);
  });

  it("round-trips the v1.3 mail group (CA pin and plaintext opt-out)", async () => {
    await engine.setConnectionConfig("secret://conn", { mail: { tls: { ca: "-----CA-----" } } });
    expect((await engine.getConnectionConfig("secret://conn"))?.mail).toEqual({
      tls: { ca: "-----CA-----" },
    });

    await engine.setConnectionConfig("secret://conn", { mail: { tls: false } });
    expect((await engine.getConnectionConfig("secret://conn"))?.mail).toEqual({ tls: false });
  });

  it("audits the mail group's TLS decision in the database group's vocabulary", async () => {
    await engine.setConnectionConfig("secret://conn", { mail: { tls: false } });
    await engine.setConnectionConfig("secret://conn", { mail: {} });

    const grants = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .filter((e) => e.detail?.policy === "connection");
    // queryAudit is newest-first.
    expect(grants[0]?.detail?.has_mail).toBe(true);
    expect(grants[0]?.detail?.has_git).toBe(false);
    expect(grants[0]?.detail?.mail_tls).toBe("require");
    expect(grants[1]?.detail?.mail_tls).toBe("disable");
  });

  it("audits the git group's presence as has_git", async () => {
    await engine.setConnectionConfig("secret://conn", {
      git: { ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" },
    });
    const grants = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .filter((e) => e.detail?.policy === "connection");
    expect(grants[0]?.detail?.has_git).toBe(true);
    expect(grants[0]?.detail?.has_mail).toBe(false);
  });

  it("audits the http group's presence as has_http (D2h)", async () => {
    await engine.setConnectionConfig("secret://conn", {
      http: { ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" },
    });
    const grants = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .filter((e) => e.detail?.policy === "connection");
    expect(grants[0]?.detail?.has_http).toBe(true);
    expect(grants[0]?.detail?.has_git).toBe(false);
  });

  const rewriteStoredConnectionConfig = async (
    handle: string,
    transform: (plaintext: string) => string,
  ): Promise<void> => {
    const secretId = await engine.resolveSecretId(handle);
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const row = store.getConnectionConfig(secretId);
    if (!row) throw new Error("no stored connection config");
    const plaintext = Buffer.from(
      decrypt(
        kek,
        row.config_encrypted,
        row.config_iv,
        row.config_tag,
        AAD_CONNECTION_CONFIG(secretId),
      ),
    ).toString("utf8");
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(transform(plaintext), "utf8")),
      AAD_CONNECTION_CONFIG(secretId),
    );
    const now = Date.now();
    store.upsertConnectionConfig({
      secret_id: secretId,
      config_encrypted: enc.ciphertext,
      config_iv: enc.iv,
      config_tag: enc.tag,
      created_at: now,
      updated_at: now,
    });
  };

  it("refuses a connection config the schema refuses before writing, naming the path (P3-11)", async () => {
    await expect(
      engine.setConnectionConfig("secret://conn", {
        database: { tls_mode: "require" },
        stray: 1,
      } as never),
    ).rejects.toMatchObject({
      code: ErrorCode.SCHEMA_VALIDATION_ERROR,
      message: expect.stringContaining(
        'Invalid connection config: <root>: Unrecognized key: "stray"',
      ),
    });
    expect(await engine.getConnectionConfig("secret://conn")).toBeUndefined();
  });

  it("a stored connection config with an unknown key is VAULT_CORRUPTED naming the path, never the key", async () => {
    await engine.setConnectionConfig("secret://conn", { database: { tls_mode: "require" } });
    await rewriteStoredConnectionConfig("secret://conn", (plaintext) =>
      JSON.stringify({ ...(JSON.parse(plaintext) as Record<string, unknown>), extra: 1 }),
    );
    const error = await engine.getConnectionConfig("secret://conn").catch((e: unknown) => e);
    expect(error).toMatchObject({ code: ErrorCode.VAULT_CORRUPTED });
    expect((error as Error).message).toContain("is malformed (<root>)");
    expect((error as Error).message).not.toContain("extra");
  });

  it("a stored connection config that is not JSON is VAULT_CORRUPTED, never a raw SyntaxError", async () => {
    await engine.setConnectionConfig("secret://conn", { database: { tls_mode: "require" } });
    await rewriteStoredConnectionConfig("secret://conn", () => "not json");
    await expect(engine.getConnectionConfig("secret://conn")).rejects.toMatchObject({
      code: ErrorCode.VAULT_CORRUPTED,
      message: expect.stringContaining("is not JSON"),
    });
  });
});

describe("the value tools' pre-flights (P3-35)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "taken",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("secretNameTaken is true for an active name, false for an unknown and for a revoked one", async () => {
    expect(await engine.secretNameTaken("taken")).toBe(true);
    expect(await engine.secretNameTaken("taken", "other-project")).toBe(false);
    expect(await engine.secretNameTaken("unknown")).toBe(false);
    await engine.revokeSecret("secret://taken");
    expect(await engine.secretNameTaken("taken")).toBe(false);
  });

  it("secretNameTaken writes no audit row", async () => {
    const before = engine.queryAudit({}).length;
    await engine.secretNameTaken("taken");
    await engine.secretNameTaken("unknown");
    expect(engine.queryAudit({}).length).toBe(before);
  });

  it("assertRotateAllowed refuses an unknown handle as SECRET_NOT_FOUND with a denied secret.rotate row", async () => {
    await expect(engine.assertRotateAllowed("secret://missing")).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });
    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_ROTATE })
      .filter((row) => row.success === false);
    expect(denied).toHaveLength(1);
    expect(denied[0]?.detail).toMatchObject({ handle: "secret://missing" });
  });

  it("assertRotateAllowed passes a granted caller and refuses a grantless one as SECRET_NOT_FOUND (R5)", async () => {
    registerAgents(engine, "rotator", "bystander");
    const granted = callerFor("rotator", ["rotate"], "agent");
    const secretId = await engine.resolveSecretId("secret://taken");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "rotator", permissions: ["rotate"] },
      "admin",
    );
    const rotateRowsBefore = engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE }).length;
    await expect(engine.assertRotateAllowed("secret://taken", granted)).resolves.toBeUndefined();
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE }).length).toBe(
      rotateRowsBefore,
    );

    const grantless = callerFor("bystander", ["rotate"], "agent");
    await expect(engine.assertRotateAllowed("secret://taken", grantless)).rejects.toMatchObject({
      code: ErrorCode.SECRET_NOT_FOUND,
    });
  });
});
