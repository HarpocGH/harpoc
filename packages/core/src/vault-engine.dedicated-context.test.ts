import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

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
  tempDir = join(tmpdir(), `harpoc-dc-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

/**
 * Engine-level pin for C1: a secret configured for the Git context necessarily
 * allowlists `git`, and `command_allowlist` is context-agnostic — so the whole
 * chain (use_secret → dispatch on caller-chosen action.type → process injector)
 * must refuse before the credential is decrypted into a child environment.
 */
describe("VaultEngine — dedicated-context refusal (C1)", () => {
  async function gitSecret(name: string): Promise<string> {
    await engine.createSecret({
      name,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("ghp_realtoken", "utf8")),
    });
    const handle = `secret://${name}`;
    // Exactly what enabling the Git context requires — nothing exotic.
    await engine.setInjectionPolicy(handle, { command_allowlist: ["git"] });
    return handle;
  }

  it("refuses a process action that re-spawns the Git context's binary", async () => {
    const handle = await gitSecret("gh-pat");
    await expect(
      engine.useSecret(handle, {
        type: "process",
        command: "git",
        args: ["-c", "alias.x=!echo pwned", "x"],
        env_var: "GH_TOKEN",
      }),
    ).rejects.toMatchObject({ code: ErrorCode.DEDICATED_CONTEXT_REQUIRED });
  });

  it("audits the refusal against the secret, with the process context named", async () => {
    const handle = await gitSecret("gh-pat");
    const secretId = await engine.resolveSecretId(handle);
    await expect(
      engine.useSecret(handle, { type: "process", command: "git", env_var: "GH_TOKEN" }),
    ).rejects.toMatchObject({ code: ErrorCode.DEDICATED_CONTEXT_REQUIRED });

    const rows = engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toMatchObject({
      context: "process",
      command: "git",
      error: ErrorCode.DEDICATED_CONTEXT_REQUIRED,
    });
  });

  it("keeps the audit chain valid across the refusal", async () => {
    const handle = await gitSecret("gh-pat");
    await expect(
      engine.useSecret(handle, { type: "process", command: "git", env_var: "GH_TOKEN" }),
    ).rejects.toMatchObject({ code: ErrorCode.DEDICATED_CONTEXT_REQUIRED });
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("negative control: the same secret still runs an ordinary allowlisted binary", async () => {
    await engine.createSecret({
      name: "api-key",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("sk-value", "utf8")),
    });
    const handle = "secret://api-key";
    // node is a known interpreter, so the acknowledgement gate applies — the two
    // gates compose: acknowledged interpreters run, dedicated-context binaries
    // do not, whatever the acknowledgement says.
    await engine.setInjectionPolicy(
      handle,
      { command_allowlist: [process.execPath] },
      { acknowledge_interpreters: true },
    );

    const result = await engine.useSecret(handle, {
      type: "process",
      command: process.execPath,
      args: ["-e", "process.stdout.write(process.env.K ? 'SET' : 'UNSET')"],
      env_var: "K",
    });
    expect(result).toMatchObject({ type: "process", exit_code: 0 });
  });
});
