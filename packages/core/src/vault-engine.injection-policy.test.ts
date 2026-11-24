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
import { registerAgents, registryOf, seedLiveStdioEntry } from "./__fixtures__/engine-seams.js";
import { decrypt, encrypt } from "./crypto/aes-gcm.js";
import {
  BLOCK,
  FP_A,
  FP_B,
  FP_HOST,
  HOST_KEY,
  KEY_A,
  KEY_B,
} from "./injection/__fixtures__/ssh-public-keys.js";
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
      proxy: false,
      ssh_agent_socket: false,
      local_dirs: [],
      ssh_bootstrap: null,
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

  it("round-trips proxy, defaults it to false when omitted, and audits it in the POLICY_GRANT detail (B2)", async () => {
    await engine.setInjectionPolicy("secret://pol", { proxy: true });
    expect((await engine.getInjectionPolicy("secret://pol")).proxy).toBe(true);
    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0]?.detail?.proxy).toBe(
      true,
    );
    await engine.setInjectionPolicy("secret://pol", { url_allowlist: [] });
    expect((await engine.getInjectionPolicy("secret://pol")).proxy).toBe(false);
    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0]?.detail?.proxy).toBe(
      false,
    );
  });

  it("round-trips ssh_agent_socket, defaults it to false when omitted, and audits it in the POLICY_GRANT detail (B3)", async () => {
    await engine.setInjectionPolicy("secret://pol", { ssh_agent_socket: true });
    expect((await engine.getInjectionPolicy("secret://pol")).ssh_agent_socket).toBe(true);
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0]?.detail?.ssh_agent_socket,
    ).toBe(true);
    await engine.setInjectionPolicy("secret://pol", { url_allowlist: [] });
    expect((await engine.getInjectionPolicy("secret://pol")).ssh_agent_socket).toBe(false);
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0]?.detail?.ssh_agent_socket,
    ).toBe(false);
  });

  it("round-trips ssh_bootstrap, reads it absent when omitted, and records it in the POLICY_GRANT detail as fingerprints", async () => {
    await engine.setInjectionPolicy("secret://pol", { ssh_bootstrap: BLOCK });
    expect((await engine.getInjectionPolicy("secret://pol")).ssh_bootstrap).toEqual(BLOCK);
    const detail = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0]?.detail;
    expect(detail?.ssh_bootstrap).toEqual({
      host: "h1.example",
      port: 22,
      user: "ubuntu",
      host_keys: [FP_HOST],
      install_keys: [FP_A, FP_B],
      sudoers: true,
    });
    for (const line of [HOST_KEY, KEY_A, KEY_B]) {
      expect(JSON.stringify(detail).includes(line.split(" ")[1] as string)).toBe(false);
    }

    await engine.setInjectionPolicy("secret://pol", {});
    expect((await engine.getInjectionPolicy("secret://pol")).ssh_bootstrap).toBeNull();
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0]?.detail?.ssh_bootstrap,
    ).toBeNull();
  });

  it.each(["oauth_token", "certificate"] as const)(
    "refuses the block on a secret that is not an api_key, with a failed policy.grant row: %s",
    async (type) => {
      await engine.createSecret({ name: "typed", type });
      const secretId = await engine.resolveSecretId("secret://typed");
      const { store } = engine as unknown as { store: SqliteStore };

      const err = await expectVaultError(
        () => engine.setInjectionPolicy("secret://typed", { ssh_bootstrap: BLOCK }),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe("ssh_bootstrap needs a secret of type api_key");
      const grants = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
      expect(grants.filter((row) => row.success)).toHaveLength(0);
      const failed = grants.filter((row) => !row.success);
      expect(failed.map((row) => row.secret_id)).toEqual([secretId]);
      expect(failed.map((row) => row.detail)).toEqual([
        {
          policy: "injection",
          handle: "secret://typed",
          error: ErrorCode.INVALID_INPUT,
          reason: "ssh_bootstrap_secret_type",
        },
      ]);
      expect(store.getInjectionPolicy(secretId)).toBeUndefined();
    },
  );

  it("refuses the block beside proxy, and beside ssh_agent_socket", async () => {
    await engine.setInjectionPolicy("secret://pol", { host_allowlist: ["a.example"] });
    const first = await engine.getInjectionPolicy("secret://pol");
    const secretId = await engine.resolveSecretId("secret://pol");
    const cases = [
      [{ proxy: true }, "ssh_bootstrap cannot stand beside proxy", "ssh_bootstrap_with_proxy"],
      [
        { ssh_agent_socket: true },
        "ssh_bootstrap cannot stand beside ssh_agent_socket",
        "ssh_bootstrap_with_ssh_agent_socket",
      ],
    ] as const;

    for (const [beside, message, reason] of cases) {
      const err = await expectVaultError(
        () => engine.setInjectionPolicy("secret://pol", { ssh_bootstrap: BLOCK, ...beside }),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(message);
      const [row] = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
      expect(row?.success).toBe(false);
      expect(row?.secret_id).toBe(secretId);
      expect(row?.detail).toEqual({
        policy: "injection",
        handle: "secret://pol",
        error: ErrorCode.INVALID_INPUT,
        reason,
      });
    }
    expect(
      engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT }).filter((row) => row.success),
    ).toHaveLength(1);
    expect(await engine.getInjectionPolicy("secret://pol")).toEqual(first);
  });

  it("answers the three refusals in their order: the type, then proxy, then ssh_agent_socket", async () => {
    await engine.createSecret({ name: "typed", type: "oauth_token" });
    const all = { ssh_bootstrap: BLOCK, proxy: true, ssh_agent_socket: true };

    const onType = await expectVaultError(
      () => engine.setInjectionPolicy("secret://typed", all),
      ErrorCode.INVALID_INPUT,
    );
    expect(onType.message).toBe("ssh_bootstrap needs a secret of type api_key");
    const beside = await expectVaultError(
      () => engine.setInjectionPolicy("secret://pol", all),
      ErrorCode.INVALID_INPUT,
    );
    expect(beside.message).toBe("ssh_bootstrap cannot stand beside proxy");
    expect(
      engine
        .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
        .map((row) => row.detail?.reason),
    ).toEqual(["ssh_bootstrap_with_proxy", "ssh_bootstrap_secret_type"]);
  });

  it("the admin gate answers first", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    registerAgents(engine, "policy-reader");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "policy-reader", permissions: ["read"] },
      "operator",
    );

    const err = await expectVaultError(
      () =>
        engine.setInjectionPolicy(
          "secret://pol",
          { ssh_bootstrap: BLOCK, proxy: true },
          undefined,
          {
            principal_type: "agent",
            principal_id: "policy-reader",
            interface: "cli",
          },
        ),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe("Access denied: Principal lacks 'admin' permission on this secret");
    expect(
      engine
        .queryAudit({ eventType: AuditEventType.POLICY_GRANT })
        .filter((row) => row.detail?.policy === "injection")
        .map((row) => row.detail),
    ).toEqual([
      {
        policy: "injection",
        handle: "secret://pol",
        required_permission: "admin",
        error: ErrorCode.ACCESS_DENIED,
        interface: "cli",
      },
    ]);
  });

  it("loads a twelve-field blob written before ssh_agent_socket existed as false — the third post-baseline read default (B3)", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const twelveFields = JSON.stringify({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["github.com"],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
      strict_tree_exit: false,
      proxy: true,
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(twelveFields, "utf8")),
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
    expect(loaded.ssh_agent_socket).toBe(false);
    expect(loaded.proxy).toBe(true);
    expect(loaded.host_allowlist).toEqual(["github.com"]);
    // No rewrite on read: the blob is the twelve-field one until the next set.
    expect(store.getInjectionPolicy(secretId)?.updated_at).toBe(now);
  });

  it("a policy stored before either key reads an empty list", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const thirteenFields = JSON.stringify({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["sftp.example.com"],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
      strict_tree_exit: false,
      proxy: false,
      ssh_agent_socket: true,
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(thirteenFields, "utf8")),
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
    expect(loaded.local_dirs).toEqual([]);
    expect(loaded.ssh_agent_socket).toBe(true);
    expect(loaded.host_allowlist).toEqual(["sftp.example.com"]);
    expect(store.getInjectionPolicy(secretId)?.updated_at).toBe(now);
  });

  it("loads a fourteen-field blob written before the block existed with the block absent — the fifth post-baseline read default", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const fourteenFields = JSON.stringify({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["sftp.example.com"],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
      strict_tree_exit: false,
      proxy: false,
      ssh_agent_socket: true,
      local_dirs: [],
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(fourteenFields, "utf8")),
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
    expect(loaded.ssh_bootstrap).toBeNull();
    expect(loaded.ssh_agent_socket).toBe(true);
    expect(loaded.host_allowlist).toEqual(["sftp.example.com"]);
    expect(store.getInjectionPolicy(secretId)?.updated_at).toBe(now);
  });

  it("the old key reads", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const oldKey = JSON.stringify({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["sftp.example.com"],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
      strict_tree_exit: false,
      proxy: false,
      ssh_agent_socket: false,
      sftp_local_dirs: ["/srv/a"],
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(oldKey, "utf8")),
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
    expect(loaded.local_dirs).toEqual(["/srv/a"]);
    expect("sftp_local_dirs" in loaded).toBe(false);
    expect(store.getInjectionPolicy(secretId)?.updated_at).toBe(now);

    await engine.setInjectionPolicy("secret://pol", {
      ...loaded,
      host_allowlist: ["sftp.example.com", "sftp2.example.com"],
    });
    const row = store.getInjectionPolicy(secretId);
    const stored = JSON.parse(
      Buffer.from(
        decrypt(
          kek,
          row?.policy_encrypted as Uint8Array,
          row?.policy_iv as Uint8Array,
          row?.policy_tag as Uint8Array,
          AAD_INJECTION_POLICY(secretId),
        ),
      ).toString("utf8"),
    ) as Record<string, unknown>;
    expect(stored["local_dirs"]).toEqual(["/srv/a"]);
    expect("sftp_local_dirs" in stored).toBe(false);
  });

  it("both keys are corruption", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const bothKeys = JSON.stringify({
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
      proxy: false,
      ssh_agent_socket: false,
      local_dirs: ["/srv/new"],
      sftp_local_dirs: ["/srv/old"],
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(bothKeys, "utf8")),
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
    expect(err.message).toBe(
      `Vault corrupted: injection policy for secret ${secretId} is malformed (<root>)`,
    );
    expect(store.getInjectionPolicy(secretId)?.updated_at).toBe(now);
  });

  it("the policy.grant row records the directories as a count", async () => {
    await engine.setInjectionPolicy("secret://pol", { local_dirs: ["/srv/out", "/srv/in"] });
    expect((await engine.getInjectionPolicy("secret://pol")).local_dirs).toEqual([
      "/srv/out",
      "/srv/in",
    ]);
    const row = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })[0];
    expect(row?.detail?.local_dir_count).toBe(2);
    expect("sftp_local_dir_count" in (row?.detail as object)).toBe(false);
    expect(JSON.stringify(row?.detail).includes("/srv/out")).toBe(false);
    expect(JSON.stringify(row?.detail).includes("/srv/in")).toBe(false);
  });

  it("loads an eleven-field blob written before proxy existed as proxy: false — the second post-baseline read default (B2)", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
    const elevenFields = JSON.stringify({
      url_allowlist: ["https://api.example.com/*"],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
      strict_tree_exit: true,
    });
    const enc = encrypt(
      kek,
      new Uint8Array(Buffer.from(elevenFields, "utf8")),
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
    expect(loaded.proxy).toBe(false);
    expect(loaded.strict_tree_exit).toBe(true);
    expect(loaded.url_allowlist).toEqual(["https://api.example.com/*"]);
    // No rewrite on read: the blob is the eleven-field one until the next set.
    expect(store.getInjectionPolicy(secretId)?.updated_at).toBe(now);
  });

  it("loads a ten-field blob written before strict_tree_exit existed as false — a post-baseline read default (D1)", async () => {
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
    expect(err.message).not.toContain("proxy");
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
    await seedLiveStdioEntry(engine, secretId);
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
    await seedLiveStdioEntry(engine, secretId);
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

  it("setting the block ends a live stdio child, once, under its own reason", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    await seedLiveStdioEntry(engine, secretId);
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await engine.setInjectionPolicy("secret://pol", {
      ssh_bootstrap: BLOCK,
      network_isolation: true,
    });

    expect(terminate).toHaveBeenCalledTimes(1);
    expect(terminate).toHaveBeenCalledWith(secretId, "ssh_bootstrap_enabled", {
      session_id: expect.any(String),
    });
    const terminates = engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("ssh_bootstrap_enabled");
  });

  it("attributes the terminate row to the caller that flipped the policy", async () => {
    const secretId = await engine.resolveSecretId("secret://pol");
    await seedLiveStdioEntry(engine, secretId);
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
    await seedLiveStdioEntry(engine, secretId);
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
    await seedLiveStdioEntry(engine, secretId);
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

  it.each(["sshpass", "scp", "ssh-agent", "podman", "nerdctl", "snap"])(
    "refuses the exec wrapper %s without acknowledgement and audits the tier",
    async (name) => {
      const err = await expectVaultError(
        () => engine.setInjectionPolicy("secret://interp", { command_allowlist: [name] }),
        ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED,
      );
      expect(err.message).toContain(`exec wrapper(s): ${name}`);
      expect((await engine.getInjectionPolicy("secret://interp")).command_allowlist).toEqual([]);

      const refused = engine.queryAudit({
        eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
      });
      expect(refused).toHaveLength(1);
      expect(refused[0]?.detail?.interpreters).toEqual([]);
      expect(refused[0]?.detail?.exec_wrappers).toEqual([name]);
    },
  );

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
