import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

let tempDir: string;
let engine: VaultEngine;

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-dd-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("target allowlists deny by default (R1, 2026-09-01)", () => {
  async function secret(name: string): Promise<string> {
    const created = await engine.createSecret({
      name,
      type: "api_key",
      value: new Uint8Array(Buffer.from("user:pass", "utf8")),
    });
    return created.handle;
  }

  function deniedRow(code: string, context: string): void {
    const row = engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .find((e) => e.detail?.error === code);
    expect(row?.success).toBe(false);
    expect(row?.detail?.context).toBe(context);
  }

  it("http: an unconfigured secret refuses every URL", async () => {
    const handle = await secret("dd-http");
    await expectVaultError(
      () =>
        engine.useSecret(handle, {
          type: "http",
          method: "GET",
          url: "https://api.example.com/data",
          injection: { type: "bearer" },
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );
    deniedRow("URL_NOT_ALLOWED", "http");
  });

  it("websocket: an unconfigured secret refuses every URL before any socket", async () => {
    const handle = await secret("dd-ws");
    await expectVaultError(
      () =>
        engine.useSecret(handle, {
          type: "websocket",
          url: "ws://127.0.0.1:1/feed",
          injection: { type: "bearer" },
        }),
      ErrorCode.URL_NOT_ALLOWED,
    );
    deniedRow("URL_NOT_ALLOWED", "websocket");
  });

  it("mcp over HTTP: an unconfigured secret refuses the configured endpoint", async () => {
    const handle = await secret("dd-mcp");
    await engine.setMcpServerConfig(handle, {
      server_name: "dd",
      transport: "http",
      url: "http://127.0.0.1:1/mcp",
    });
    await expectVaultError(
      () => engine.useSecret(handle, { type: "mcp", server: "dd", tool: "echo" }),
      ErrorCode.URL_NOT_ALLOWED,
    );
  });

  it("database: an unconfigured secret refuses every host:port before connecting", async () => {
    const handle = await secret("dd-db");
    await expectVaultError(
      () =>
        engine.useSecret(handle, {
          type: "database",
          engine: "postgresql",
          host: "8.8.8.8",
          database: "app",
          query: "SELECT 1",
        }),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    deniedRow("HOST_NOT_ALLOWED", "database");
  });

  it("smtp: an unconfigured secret refuses every host before any socket", async () => {
    const handle = await secret("dd-smtp");
    await engine.setConnectionConfig(handle, { mail: { tls: false } });
    await expectVaultError(
      () =>
        engine.useSecret(handle, {
          type: "smtp",
          host: "127.0.0.1",
          port: 2525,
          security: "tls",
          from: "a@example.com",
          to: ["b@example.com"],
          subject: "x",
          text: "y",
        }),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    deniedRow("HOST_NOT_ALLOWED", "smtp");
  });

  it("imap: an unconfigured secret refuses every host before any socket", async () => {
    const handle = await secret("dd-imap");
    await engine.setConnectionConfig(handle, { mail: { tls: { ca: "" } } });
    await expectVaultError(
      () =>
        engine.useSecret(handle, {
          type: "imap",
          host: "127.0.0.1",
          port: 993,
          mailbox: "INBOX",
          operation: { kind: "search", unseen: true },
        }),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    deniedRow("HOST_NOT_ALLOWED", "imap");
  });
});
