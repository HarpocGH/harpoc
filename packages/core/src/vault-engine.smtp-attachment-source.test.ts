import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SmtpAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine | undefined;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-smtpsrc-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
});

afterEach(async () => {
  await engine?.destroy();
  engine = undefined;
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function mailVault(dbPath: string, sessionPath: string): Promise<VaultEngine> {
  engine = new VaultEngine({ dbPath, sessionPath });
  await engine.initVault("password");
  await engine.createSecret({
    name: "mail",
    type: "api_key",
    value: new Uint8Array(Buffer.from("ops@example.com:S3CRET-TOKEN-xyz")),
  });
  await engine.setInjectionPolicy("secret://mail", {
    host_allowlist: ["10.0.0.1"],
    smtp_recipient_allowlist: ["*@example.com"],
  });
  return engine;
}

function send(path: string): SmtpAction {
  return {
    type: "smtp",
    host: "10.0.0.1",
    security: "tls",
    from: "ops@example.com",
    to: ["dev@example.com"],
    subject: "files",
    text: "attached",
    attachments: [{ path }],
  };
}

function failedUseRows(vault: VaultEngine): (Record<string, unknown> | null)[] {
  return vault
    .queryAudit({ eventType: AuditEventType.SECRET_USE, success: false })
    .map((row) => row.detail);
}

describe("useSecret (smtp) — the engine's injector refuses the vault's own files (B1)", () => {
  for (const file of ["test.vault.db", "session.json"]) {
    it(`refuses ${file} as an attachment with a failed secret.use row`, async () => {
      const dir = join(tempDir, "vault");
      mkdirSync(dir);
      const vault = await mailVault(join(dir, "test.vault.db"), join(dir, "session.json"));
      const path = join(dir, file);

      const err = await expectVaultError(
        () => vault.useSecret("secret://mail", send(path)),
        ErrorCode.ATTACHMENT_REJECTED,
      );

      expect(err.message).toBe(
        "Attachment rejected: an attachment path is inside the vault directory",
      );
      expect(failedUseRows(vault)).toEqual([
        {
          context: "smtp",
          host: "10.0.0.1",
          from: "ops@example.com",
          recipients: ["dev@example.com"],
          attachment_paths: [path],
          attachment_total_bytes: 0,
          error: ErrorCode.ATTACHMENT_REJECTED,
        },
      ]);
    });
  }

  it("refuses the session file when it lives in a directory of its own", async () => {
    const dbDir = join(tempDir, "db");
    const sessionDir = join(tempDir, "session");
    mkdirSync(dbDir);
    mkdirSync(sessionDir);
    const vault = await mailVault(join(dbDir, "test.vault.db"), join(sessionDir, "session.json"));

    const err = await expectVaultError(
      () => vault.useSecret("secret://mail", send(join(sessionDir, "session.json"))),
      ErrorCode.ATTACHMENT_REJECTED,
    );

    expect(err.message).toBe(
      "Attachment rejected: an attachment path is inside the vault directory",
    );
  });

  it("lets a file outside the vault directory past the source checks (refused later by the SSRF floor)", async () => {
    const dir = join(tempDir, "vault");
    const outside = join(tempDir, "outside");
    mkdirSync(dir);
    mkdirSync(outside);
    writeFileSync(join(outside, "report.txt"), "quarterly report");
    const vault = await mailVault(join(dir, "test.vault.db"), join(dir, "session.json"));

    await expectVaultError(
      () => vault.useSecret("secret://mail", send(join(outside, "report.txt"))),
      ErrorCode.SSRF_BLOCKED,
    );
  });
});
