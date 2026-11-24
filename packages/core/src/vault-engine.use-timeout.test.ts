import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { UseSecretAction } from "@harpoc/shared";
import { AuditEventType, DatabaseEngine, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(
    tmpdir(),
    `harpoc-use-timeout-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

interface EngineInternals {
  secretManager: { getSecretValue: (handle: string) => Promise<Uint8Array> };
}

async function initWithSecret(name: string, value: string): Promise<void> {
  await engine.initVault("password");
  await engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(value)),
  });
}

function useRows(
  success?: boolean,
): { detail: Record<string, unknown> | null; success: boolean }[] {
  return engine
    .queryAudit({ eventType: AuditEventType.SECRET_USE })
    .filter((row) => success === undefined || row.success === success)
    .map((row) => ({ detail: row.detail, success: row.success }));
}

const HANDLE = "secret://k";
const CONTEXTS = [
  "http",
  "process",
  "mcp",
  "git",
  "ssh",
  "sftp",
  "docker_registry",
  "smtp",
  "imap",
  "websocket",
] as const;

function unparsed(fields: Record<string, unknown>): UseSecretAction {
  return fields as unknown as UseSecretAction;
}

describe("useSecret — an out-of-schema timeout_ms of an unparsed caller", () => {
  beforeEach(async () => {
    await initWithSecret("k", "value-for-no-injector");
  });

  it.each(CONTEXTS)("%s: refused before the decrypt with one failed row", async (type) => {
    const getSecretValue = vi.spyOn(
      (engine as unknown as EngineInternals).secretManager,
      "getSecretValue",
    );
    try {
      await expectVaultError(
        () =>
          engine.useSecret(
            HANDLE,
            unparsed({
              type,
              security: "tls",
              ...(type === "ssh" ? {} : { operation: { kind: "search" } }),
              timeout_ms: 0,
            }),
          ),
        ErrorCode.INVALID_INPUT,
      );

      expect(getSecretValue).not.toHaveBeenCalled();
      const rows = useRows();
      expect(rows).toHaveLength(1);
      expect(rows[0]?.success).toBe(false);
      expect(rows[0]?.detail).toStrictEqual({
        handle: HANDLE,
        context: type,
        error: ErrorCode.INVALID_INPUT,
      });
    } finally {
      getSecretValue.mockRestore();
    }
  });

  it("a timeout_ms at the cap passes the guard and reaches the context's own refusal", async () => {
    const getSecretValue = vi.spyOn(
      (engine as unknown as EngineInternals).secretManager,
      "getSecretValue",
    );
    try {
      await expectVaultError(
        () =>
          engine.useSecret(
            HANDLE,
            unparsed({
              type: "process",
              command: "harpoc-no-such-binary",
              env_var: "TOKEN",
              timeout_ms: 300_000,
            }),
          ),
        ErrorCode.COMMAND_NOT_ALLOWED,
      );
      expect(getSecretValue).toHaveBeenCalledTimes(1);
    } finally {
      getSecretValue.mockRestore();
    }
  });

  it("the database context keeps its own refusal, after the decrypt", async () => {
    const getSecretValue = vi.spyOn(
      (engine as unknown as EngineInternals).secretManager,
      "getSecretValue",
    );
    try {
      await expectVaultError(
        () =>
          engine.useSecret(
            HANDLE,
            unparsed({
              type: "database",
              engine: DatabaseEngine.POSTGRESQL,
              host: "db.example.com",
              database: "app",
              query: "select 1",
              timeout_ms: 0,
            }),
          ),
        ErrorCode.INVALID_DATABASE_CONFIG,
      );
      expect(getSecretValue).toHaveBeenCalledTimes(1);
    } finally {
      getSecretValue.mockRestore();
    }
  });
});
