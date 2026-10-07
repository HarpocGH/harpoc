import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, injectionPolicyInputSchema } from "@harpoc/shared";
import { AAD_INJECTION_POLICY } from "@harpoc/shared";
import type { InjectionPolicyInput } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents, registryOf } from "./__fixtures__/engine-seams.js";
import { encrypt } from "./crypto/aes-gcm.js";
import type { McpConnectionEntry } from "./injection/mcp-registry.js";
import { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

// Test HTTP server
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const auth = (req.headers["authorization"] ?? "none") as string;
    if (req.url?.startsWith("/redirect-hop")) {
      res.writeHead(302, { Location: `http://${req.headers.host ?? "127.0.0.1"}/target` });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    if (req.url?.startsWith("/enc")) {
      // Echo the bearer token in encoded forms (sanitizer-bypass probes)
      const token = auth.replace("Bearer ", "");
      res.end(
        JSON.stringify({
          b64: Buffer.from(token).toString("base64"),
          hex: Buffer.from(token).toString("hex"),
          pct: encodeURIComponent(token),
        }),
      );
      return;
    }
    res.end(JSON.stringify({ authorization: auth, path: req.url }));
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  server.close();
});

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

/**
 * Publish a ready stdio entry into the engine's registry without spawning a
 * child: the terminate-on-enable paths only need something live to tear down.
 */
async function seedLiveStdioEntry(secretId: string): Promise<void> {
  const client = { onclose: undefined, close: () => Promise.resolve() };
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

describe("injection policy", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "pol",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("round-trips a policy", async () => {
    await engine.setInjectionPolicy("secret://pol", {
      url_allowlist: [`${baseUrl}/*`],
      command_allowlist: ["gh"],
      env_allowlist: ["HOME"],
      host_allowlist: ["db.example.com:5432"],
      response_mode: "status_only",
      response_header_allowlist: ["Content-Type"],
    });
    const p = await engine.getInjectionPolicy("secret://pol");
    expect(p.url_allowlist).toEqual([`${baseUrl}/*`]);
    expect(p.command_allowlist).toEqual(["gh"]);
    expect(p.env_allowlist).toEqual(["HOME"]);
    expect(p.host_allowlist).toEqual(["db.example.com:5432"]);
    expect(p.response_mode).toBe("status_only");
    expect(p.response_header_allowlist).toEqual(["Content-Type"]);
  });

  it("returns empty allowlists when no policy is set", async () => {
    const p = await engine.getInjectionPolicy("secret://pol");
    expect(p).toEqual({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
      strict_tree_exit: false,
    });
  });

  it("defaults response mode fields on a policy set without them", async () => {
    await engine.setInjectionPolicy("secret://pol", {
      url_allowlist: [`${baseUrl}/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    const p = await engine.getInjectionPolicy("secret://pol");
    expect(p.response_mode).toBe("filtered");
    expect(p.response_header_allowlist).toEqual([]);
  });

  it("refuses an unknown key as SCHEMA_VALIDATION naming it, and stores nothing (D2c)", async () => {
    const err = await expectVaultError(
      () =>
        engine.setInjectionPolicy("secret://pol", {
          network_isolaton: true,
        } as unknown as InjectionPolicyInput),
      ErrorCode.SCHEMA_VALIDATION_ERROR,
    );
    expect(err.message).toContain('Unrecognized key: "network_isolaton"');
    const grants = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .filter((e) => e.detail?.policy === "injection");
    expect(grants).toHaveLength(0);
  });

  it("stores the schema's defaults for an empty input (D2c)", async () => {
    await engine.setInjectionPolicy("secret://pol", {});
    expect(await engine.getInjectionPolicy("secret://pol")).toEqual(
      injectionPolicyInputSchema.parse({}),
    );
  });

  it("audits a policy change as POLICY_GRANT", async () => {
    await engine.setInjectionPolicy("secret://pol", {
      url_allowlist: [],
      command_allowlist: ["gh"],
      env_allowlist: [],
    });
    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0]?.detail?.policy).toBe("injection");
    expect(events[0]?.detail?.response_mode).toBe("filtered");
    expect(events[0]?.detail?.network_isolation).toBe(false);
  });

  it("round-trips network_isolation and defaults it to false when omitted", async () => {
    await engine.setInjectionPolicy("secret://pol", { network_isolation: true });
    expect((await engine.getInjectionPolicy("secret://pol")).network_isolation).toBe(true);

    // Re-set without the field: the write-side default is false (the read-side
    // `?? false` for pre-feature blobs follows the response_mode precedent).
    await engine.setInjectionPolicy("secret://pol", { url_allowlist: [] });
    expect((await engine.getInjectionPolicy("secret://pol")).network_isolation).toBe(false);
  });

  it("audits network_isolation in the POLICY_GRANT detail both ways", async () => {
    await engine.setInjectionPolicy("secret://pol", { network_isolation: true });
    await engine.setInjectionPolicy("secret://pol", {});
    const flags = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .map((e) => e.detail?.network_isolation);
    expect(flags).toContain(true);
    expect(flags).toContain(false);
  });

  it("round-trips fs_isolation and defaults it to false when omitted", async () => {
    await engine.setInjectionPolicy("secret://pol", { fs_isolation: true });
    expect((await engine.getInjectionPolicy("secret://pol")).fs_isolation).toBe(true);

    // Re-set without the field: the write-side default is false, mirroring
    // network_isolation.
    await engine.setInjectionPolicy("secret://pol", { url_allowlist: [] });
    expect((await engine.getInjectionPolicy("secret://pol")).fs_isolation).toBe(false);
  });

  it("round-trips the v1.3 mail policy fields and defaults them when omitted", async () => {
    await engine.setInjectionPolicy("secret://pol", {
      smtp_recipient_allowlist: ["ops@example.com", "*@example.org"],
      imap_read_only: true,
    });
    const p = await engine.getInjectionPolicy("secret://pol");
    expect(p.smtp_recipient_allowlist).toEqual(["ops@example.com", "*@example.org"]);
    expect(p.imap_read_only).toBe(true);

    // Re-set without them: the write-side defaults are `[]`/false, following
    // the network_isolation precedent (replace, never merge).
    await engine.setInjectionPolicy("secret://pol", { url_allowlist: [] });
    const cleared = await engine.getInjectionPolicy("secret://pol");
    expect(cleared.smtp_recipient_allowlist).toEqual([]);
    expect(cleared.imap_read_only).toBe(false);
  });

  it("audits the v1.3 policy fields in the POLICY_GRANT detail", async () => {
    await engine.setInjectionPolicy("secret://pol", {
      smtp_recipient_allowlist: ["ops@example.com"],
      imap_read_only: true,
    });
    const grant = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0];
    expect(grant?.detail?.recipient_count).toBe(1);
    expect(grant?.detail?.imap_read_only).toBe(true);
  });

  it("round-trips strict_tree_exit and defaults it to false when omitted (2026-09-10)", async () => {
    await engine.setInjectionPolicy("secret://pol", { strict_tree_exit: true });
    const granted = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0];
    expect(granted?.detail?.strict_tree_exit).toBe(true);
    expect((await engine.getInjectionPolicy("secret://pol")).strict_tree_exit).toBe(true);
    await engine.setInjectionPolicy("secret://pol", { url_allowlist: [] });
    expect((await engine.getInjectionPolicy("secret://pol")).strict_tree_exit).toBe(false);
    const grant = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0];
    expect(grant?.detail?.strict_tree_exit).toBe(false);
  });

  it("loads a ten-field blob written before strict_tree_exit existed as false — the one post-baseline read default (D1)", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const tenFields = JSON.stringify({
      url_allowlist: [],
      command_allowlist: ["gh"],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: true,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(tenFields, "utf8")),
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
    const loaded = await engine.getInjectionPolicy("secret://pol");
    expect(loaded.strict_tree_exit).toBe(false);
    expect(loaded.fs_isolation).toBe(true);
    // No rewrite on read: the blob is the ten-field one until the next set.
    expect(store.getInjectionPolicy(secretId)?.updated_at).toBe(now);
  });

  it("refuses a stored policy blob missing a key as VAULT_CORRUPTED, naming the path (R2/C43)", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const legacy = JSON.stringify({
      url_allowlist: [],
      command_allowlist: ["gh"],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(legacy, "utf8")),
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

    const err = await expectVaultError(
      () => engine.getInjectionPolicy("secret://pol"),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(err.message).toContain(`injection policy for secret ${secretId} is malformed`);
    expect(err.message).toContain("fs_isolation");
    expect(err.message).not.toContain("strict_tree_exit");
    expect(err.message).not.toContain("gh");
  });

  it("refuses a stored policy blob with an unknown key and one that is not JSON", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const write = (plaintext: string): void => {
      const enc = encrypt(
        kek,
        new Uint8Array(Buffer.from(plaintext, "utf8")),
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
    };

    write(JSON.stringify({ ...(await engine.getInjectionPolicy("secret://pol")), extra: 1 }));
    const unknownKey = await expectVaultError(
      () => engine.getInjectionPolicy("secret://pol"),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(unknownKey.message).toContain("<root>");
    expect(unknownKey.message).not.toContain("extra");

    write("not json");
    const err = await expectVaultError(
      () => engine.getInjectionPolicy("secret://pol"),
      ErrorCode.VAULT_CORRUPTED,
    );
    expect(err.message).toContain("is not JSON");
  });

  it("refuses a policy whose values fail the shared validators before writing (the strict read must never see one)", async () => {
    await engine.setInjectionPolicy("secret://pol", { command_allowlist: ["gh"] });

    const err = await expectVaultError(
      () => engine.setInjectionPolicy("secret://pol", { env_allowlist: ["1BAD"] }),
      ErrorCode.SCHEMA_VALIDATION_ERROR,
    );
    expect(err.message).toContain("env_allowlist");
    expect(err.message).not.toContain("1BAD");

    const p = await engine.getInjectionPolicy("secret://pol");
    expect(p.command_allowlist).toEqual(["gh"]);
    expect(p.env_allowlist).toEqual([]);
  });

  // D5/R7: zod's `invalid_enum_value` message quotes the rejected value back,
  // so a refusal echoed whatever the caller sent. The shared renderer names the
  // legal set instead; the value never reaches the message.
  it("names the legal enum values without echoing the rejected one", async () => {
    const err = await expectVaultError(
      () =>
        engine.setInjectionPolicy("secret://pol", {
          response_mode: "1BAD",
        } as unknown as InjectionPolicyInput),
      ErrorCode.SCHEMA_VALIDATION_ERROR,
    );
    expect(err.message).toContain("response_mode: must be one of full, filtered, status_only");
    expect(err.message).not.toContain("1BAD");
  });

  it("control: a complete stored policy round-trips unchanged", async () => {
    await engine.setInjectionPolicy("secret://pol", {
      command_allowlist: ["gh"],
      fs_isolation: true,
    });
    const p = await engine.getInjectionPolicy("secret://pol");
    expect(p.command_allowlist).toEqual(["gh"]);
    expect(p.fs_isolation).toBe(true);
    expect(p.imap_read_only).toBe(false);
  });

  it("audits fs_isolation in the POLICY_GRANT detail both ways", async () => {
    await engine.setInjectionPolicy("secret://pol", { fs_isolation: true });
    await engine.setInjectionPolicy("secret://pol", {});
    const flags = engine
      .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
      .map((e) => e.detail?.fs_isolation);
    expect(flags).toContain(true);
    expect(flags).toContain(false);
  });

  it("terminates a live stdio child when fs_isolation is enabled", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    await seedLiveStdioEntry(secretId);
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await engine.setInjectionPolicy("secret://pol", { fs_isolation: true });

    expect(terminate).toHaveBeenCalledTimes(1);
    expect(terminate).toHaveBeenCalledWith(secretId, "fs_isolation_enabled", {
      session_id: expect.any(String),
    });
    const terminates = engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("fs_isolation_enabled");
  });

  it("terminates a live stdio child when strict_tree_exit is enabled (D2, 2026-09-10)", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    await seedLiveStdioEntry(secretId);
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await engine.setInjectionPolicy("secret://pol", { strict_tree_exit: true });

    expect(terminate).toHaveBeenCalledTimes(1);
    expect(terminate).toHaveBeenCalledWith(secretId, "strict_tree_exit_enabled", {
      session_id: expect.any(String),
    });
    const terminates = engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("strict_tree_exit_enabled");
  });

  it("attributes the terminate row to the caller that flipped the policy", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    await seedLiveStdioEntry(secretId);
    registerAgents(engine, "policy-admin");
    engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "policy-admin",
        permissions: ["admin"],
      },
      "operator",
    );

    await engine.setInjectionPolicy("secret://pol", { fs_isolation: true }, undefined, {
      principal_type: "agent",
      principal_id: "policy-admin",
      interface: "cli",
    });

    const [row] = engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(row?.principal_type).toBe("agent");
    expect(row?.principal_id).toBe("policy-admin");
    expect(row?.detail).toMatchObject({ reason: "fs_isolation_enabled", interface: "cli" });
  });

  it("terminates once with the network reason when both isolation flags are enabled", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    await seedLiveStdioEntry(secretId);
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await engine.setInjectionPolicy("secret://pol", {
      network_isolation: true,
      fs_isolation: true,
    });

    expect(terminate).toHaveBeenCalledTimes(1);
    expect(terminate).toHaveBeenCalledWith(secretId, "network_isolation_enabled", {
      session_id: expect.any(String),
    });
    const terminates = engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("network_isolation_enabled");
  });

  it("control: a policy set without either isolation flag leaves the child alive", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    await seedLiveStdioEntry(secretId);
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await engine.setInjectionPolicy("secret://pol", { url_allowlist: [] });

    expect(terminate).not.toHaveBeenCalled();
    expect(engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE })).toHaveLength(0);
  });

  it("verifies the audit chain and detects DB tampering", async () => {
    await engine.createSecret({
      name: "chained",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const clean = engine.verifyAuditChain();
    expect(clean.valid).toBe(true);
    expect(clean.checked).toBeGreaterThan(0);

    // Tamper directly in the DB (attacker with write access, no audit key).
    const db = new Database(dbPath);
    const target = db.prepare("SELECT id FROM audit_log ORDER BY id LIMIT 1").get() as {
      id: number;
    };
    db.prepare("UPDATE audit_log SET success = 0 WHERE id = ?").run(target.id);
    db.close();

    const tampered = engine.verifyAuditChain();
    expect(tampered.valid).toBe(false);
    expect(tampered.firstBrokenId).toBe(target.id);
  });
});

describe("interpreter acknowledgement (thesis §4.5.3)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "interp",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("refuses to add a known interpreter without acknowledgement and audits the refusal", async () => {
    await expectVaultError(
      () =>
        engine.setInjectionPolicy("secret://interp", {
          url_allowlist: [],
          command_allowlist: ["python"],
          env_allowlist: [],
        }),
      ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
    );
    // The policy is unchanged and no grant was recorded
    const p = await engine.getInjectionPolicy("secret://interp");
    expect(p.command_allowlist).toEqual([]);
    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })).toHaveLength(0);

    const refused = engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
    });
    expect(refused).toHaveLength(1);
    expect(refused[0]?.detail?.policy).toBe("injection");
    expect(refused[0]?.detail?.interpreters).toEqual(["python"]);
    expect(refused[0]?.detail?.exec_wrappers).toEqual([]);
  });

  it("accepts an acknowledged interpreter addition and audits it", async () => {
    await engine.setInjectionPolicy(
      "secret://interp",
      { url_allowlist: [], command_allowlist: ["python"], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    const p = await engine.getInjectionPolicy("secret://interp");
    expect(p.command_allowlist).toEqual(["python"]);

    const acked = engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED,
    });
    expect(acked).toHaveLength(1);
    expect(acked[0]?.detail?.interpreters).toEqual(["python"]);
    expect(acked[0]?.detail?.exec_wrappers).toEqual([]);
    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })).toHaveLength(1);
  });

  it("R6(ii): refuses an exec wrapper without acknowledgement and audits the tier", async () => {
    const err = await expectVaultError(
      () =>
        engine.setInjectionPolicy("secret://interp", {
          url_allowlist: [],
          command_allowlist: ["sudo"],
          env_allowlist: [],
        }),
      ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
    );
    expect(err.message).toContain("exec wrapper(s): sudo");
    expect(err.message).not.toContain("known interpreter(s)");
    expect((await engine.getInjectionPolicy("secret://interp")).command_allowlist).toEqual([]);

    const refused = engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
    });
    expect(refused).toHaveLength(1);
    expect(refused[0]?.detail?.interpreters).toEqual([]);
    expect(refused[0]?.detail?.exec_wrappers).toEqual(["sudo"]);
  });

  it("R6(ii): names both tiers when one write adds an interpreter and a wrapper", async () => {
    const err = await expectVaultError(
      () =>
        engine.setInjectionPolicy("secret://interp", {
          url_allowlist: [],
          command_allowlist: ["python", "/usr/bin/tar"],
          env_allowlist: [],
        }),
      ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
    );
    expect(err.message).toContain("known interpreter(s): python and exec wrapper(s): /usr/bin/tar");

    const refused = engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
    });
    expect(refused).toHaveLength(1);
    expect(refused[0]?.detail?.interpreters).toEqual(["python"]);
    expect(refused[0]?.detail?.exec_wrappers).toEqual(["/usr/bin/tar"]);
  });

  it("R6(ii): accepts an acknowledged exec wrapper under the same flag and audits it", async () => {
    await engine.setInjectionPolicy(
      "secret://interp",
      { url_allowlist: [], command_allowlist: ["xargs"], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    expect((await engine.getInjectionPolicy("secret://interp")).command_allowlist).toEqual([
      "xargs",
    ]);

    const acked = engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED,
    });
    expect(acked).toHaveLength(1);
    expect(acked[0]?.detail?.interpreters).toEqual([]);
    expect(acked[0]?.detail?.exec_wrappers).toEqual(["xargs"]);
    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })).toHaveLength(1);
  });

  it("detects interpreters by basename across paths, extensions and versions", async () => {
    for (const entry of [
      "/usr/local/bin/python3.12",
      "C:\\Program Files\\nodejs\\node.exe",
      "bash",
    ]) {
      await expectVaultError(
        () =>
          engine.setInjectionPolicy("secret://interp", {
            url_allowlist: [],
            command_allowlist: [entry],
            env_allowlist: [],
          }),
        ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
      );
    }
  });

  it("does not re-gate an interpreter already on the stored allowlist", async () => {
    await engine.setInjectionPolicy(
      "secret://interp",
      { url_allowlist: [], command_allowlist: ["python"], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    // Re-asserting the stored entry while changing another group needs no flag
    await engine.setInjectionPolicy("secret://interp", {
      url_allowlist: ["https://api.example.com/*"],
      command_allowlist: ["python"],
      env_allowlist: [],
    });
    const p = await engine.getInjectionPolicy("secret://interp");
    expect(p.url_allowlist).toEqual(["https://api.example.com/*"]);
    expect(p.command_allowlist).toEqual(["python"]);
    // Exactly one acknowledgement in the trail — the original addition
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED }),
    ).toHaveLength(1);
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_REFUSED }),
    ).toHaveLength(0);
  });

  it("gates each newly added interpreter entry, reporting only the new ones", async () => {
    await engine.setInjectionPolicy(
      "secret://interp",
      { url_allowlist: [], command_allowlist: ["python"], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await expectVaultError(
      () =>
        engine.setInjectionPolicy("secret://interp", {
          url_allowlist: [],
          command_allowlist: ["python", "bash"],
          env_allowlist: [],
        }),
      ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
    );
    const refused = engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
    });
    expect(refused).toHaveLength(1);
    expect(refused[0]?.detail?.interpreters).toEqual(["bash"]);
  });

  it("gates a symlink whose resolved target is a known interpreter (E71 — resolved-path parity with the use-time gate)", async (ctx) => {
    const target =
      process.platform === "win32"
        ? join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe")
        : "/bin/sh";
    const link = join(tempDir, process.platform === "win32" ? "runner.exe" : "runner");
    try {
      symlinkSync(target, link, "file");
    } catch {
      // Symlink creation needs privileges this host may not grant (the
      // allowlist.test.ts precedent) — skipped, never silently passed.
      return ctx.skip();
    }

    await expectVaultError(
      () => engine.setInjectionPolicy("secret://interp", { command_allowlist: [link] }),
      ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
    );
    const refused = engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_REFUSED });
    expect(refused).toHaveLength(1);
    expect(refused[0]?.detail?.interpreters).toEqual([link]);

    await engine.setInjectionPolicy(
      "secret://interp",
      { command_allowlist: [link] },
      { acknowledge_interpreters: true },
    );
    expect((await engine.getInjectionPolicy("secret://interp")).command_allowlist).toEqual([link]);
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED }),
    ).toHaveLength(1);
  });

  it("never gates non-interpreter commands", async () => {
    // Chosen to resolve to nothing or to a non-interpreter on every CI image.
    await engine.setInjectionPolicy("secret://interp", {
      url_allowlist: [],
      command_allowlist: ["gh", "/usr/bin/git"],
      env_allowlist: [],
    });
    const p = await engine.getInjectionPolicy("secret://interp");
    expect(p.command_allowlist).toEqual(["gh", "/usr/bin/git"]);
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_REFUSED }),
    ).toHaveLength(0);
  });

  it("logs no acknowledgement event when the flag is passed without interpreters", async () => {
    await engine.setInjectionPolicy(
      "secret://interp",
      { url_allowlist: [], command_allowlist: ["gh"], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_INTERPRETER_ACKNOWLEDGED }),
    ).toHaveLength(0);
  });
});
