import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, VaultError, VaultState } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";
import { DpapiSessionKeyProtector } from "./session/session-key-protector.js";
import type { SessionKeyProtector } from "./session/session-key-protector.js";

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
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

// Test HTTP server
let server: Server;
let baseUrl: string;
let requestCount = 0;

beforeAll(async () => {
  server = createServer((req, res) => {
    requestCount++;
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
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("lifecycle", () => {
  it("starts sealed", () => {
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("initializes and unlocks a new vault", async () => {
    const { vaultId } = await engine.initVault("password");
    expect(vaultId).toBeTruthy();
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
  });

  it("locks and seals", async () => {
    await engine.initVault("password");
    await engine.lock();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("unlocks an existing vault", async () => {
    await engine.initVault("my-pass1");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("my-pass1");
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
    await engine2.destroy();
  });

  it("rejects wrong password on unlock", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await expect(engine2.unlock("wrong123")).rejects.toThrow(VaultError);

    try {
      await engine2.unlock("wrong123");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PASSWORD);
    }
    await engine2.destroy();
  });

  it("rejects operations when sealed", async () => {
    expect(() => engine.listSecrets()).toThrow(VaultError);

    try {
      engine.listSecrets();
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });

  it("loadSession closes store on vault_id mismatch (no handle leak)", async () => {
    await engine.initVault("password");
    // destroy preserves session file, unlike lock which erases it
    await engine.destroy();

    // Tamper session file vault_id
    const raw = readFileSync(sessionPath, "utf-8");
    const session = JSON.parse(raw);
    session.vault_id = "tampered-vault-id";
    writeFileSync(sessionPath, JSON.stringify(session));

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const result = await engine2.loadSession();
    expect(result).toBe(false);
    expect(engine2.getState()).toBe(VaultState.SEALED);
    // engine2 should not have a store to close — no leaked handle
    await engine2.destroy();
  });

  it("rejects weak password on initVault", async () => {
    try {
      await engine.initVault("short");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.WEAK_PASSWORD);
    }
  });
});

describe("secrets", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates and lists secrets", async () => {
    await engine.createSecret({
      name: "test-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-value")),
    });

    const list = engine.listSecrets();
    expect(list.length).toBe(1);
    expect(list[0]?.name).toBe("test-key");
  });

  it("creates and retrieves secret info", async () => {
    await engine.createSecret({
      name: "info-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    const info = await engine.getSecretInfo("secret://info-key");
    expect(info.name).toBe("info-key");
    expect(info.status).toBe("active");
  });

  it("creates and retrieves secret value", async () => {
    await engine.createSecret({
      name: "get-val",
      type: "api_key",
      value: new Uint8Array(Buffer.from("the-secret")),
    });

    const value = await engine.getSecretValue("secret://get-val");
    expect(Buffer.from(value).toString()).toBe("the-secret");
  });

  it("handles pending → set value flow", async () => {
    await engine.createSecret({ name: "pending", type: "api_key" });
    await engine.setSecretValue("secret://pending", new Uint8Array(Buffer.from("now-set")));

    const info = await engine.getSecretInfo("secret://pending");
    expect(info.status).toBe("active");
  });

  it("rotates a secret", async () => {
    await engine.createSecret({
      name: "rotate-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });

    await engine.rotateSecret("secret://rotate-me", new Uint8Array(Buffer.from("new")));

    const info = await engine.getSecretInfo("secret://rotate-me");
    expect(info.version).toBe(2);

    const value = await engine.getSecretValue("secret://rotate-me");
    expect(Buffer.from(value).toString()).toBe("new");
  });

  it("revokes a secret", async () => {
    await engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.revokeSecret("secret://rev");

    const info = await engine.getSecretInfo("secret://rev");
    expect(info.status).toBe("revoked");
  });
});

describe("error propagation through VaultEngine", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("getSecretInfo throws SECRET_NOT_FOUND for non-existent handle", async () => {
    try {
      await engine.getSecretInfo("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("getSecretValue throws SECRET_NOT_FOUND for non-existent handle", async () => {
    try {
      await engine.getSecretValue("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("getSecretInfo throws INVALID_HANDLE for malformed handle", async () => {
    try {
      await engine.getSecretInfo("not-a-handle");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_HANDLE);
    }
  });

  it("getSecretValue throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://rev");

    try {
      await engine.getSecretValue("secret://rev");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("getSecretValue throws SECRET_VALUE_REQUIRED for pending secret", async () => {
    await engine.createSecret({ name: "pend", type: "api_key" });

    try {
      await engine.getSecretValue("secret://pend");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_VALUE_REQUIRED);
    }
  });

  it("createSecret throws DUPLICATE_SECRET for duplicate name", async () => {
    await engine.createSecret({
      name: "dup",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.createSecret({
        name: "dup",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.DUPLICATE_SECRET);
    }
  });

  it("rotateSecret throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "rot-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://rot-rev");

    try {
      await engine.rotateSecret("secret://rot-rev", new Uint8Array(Buffer.from("new")));
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("useSecret throws SECRET_NOT_FOUND for non-existent handle", async () => {
    try {
      await engine.useSecret("secret://nonexistent", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/test`,
        injection: { type: "bearer" },
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("useSecret throws SECRET_REVOKED for revoked secret", async () => {
    await engine.createSecret({
      name: "use-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    await engine.revokeSecret("secret://use-rev");

    try {
      await engine.useSecret("secret://use-rev", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/test`,
        injection: { type: "bearer" },
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("useSecret throws URL_INVALID for invalid URL", async () => {
    await engine.createSecret({
      name: "url-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.useSecret("secret://url-test", {
        type: "http",
        method: "GET",
        url: "not-a-url",
        injection: { type: "bearer" },
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_INVALID);
    }
  });

  it("useSecret throws SSRF_BLOCKED for private IP", async () => {
    await engine.createSecret({
      name: "ssrf-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.useSecret("secret://ssrf-test", {
        type: "http",
        method: "GET",
        url: "https://10.0.0.1/api",
        injection: { type: "bearer" },
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });
});

describe("useSecret (HTTP injection)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("injects bearer token and returns response", async () => {
    await engine.createSecret({
      name: "api-token",
      type: "api_key",
      value: new Uint8Array(Buffer.from("my-bearer-token")),
    });

    const response = await engine.useSecret("secret://api-token", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/test`,
      injection: { type: "bearer" },
    });

    expect(response.type).toBe("http");
    if (response.type !== "http") throw new Error("expected http result");
    expect(response.status).toBe(200);
    const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
    // Exact-match redaction scrubs the secret value from reflected responses
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });
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
    try {
      await engine.setInjectionPolicy("secret://interp", {
        url_allowlist: [],
        command_allowlist: ["python"],
        env_allowlist: [],
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED);
    }
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
    expect(engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT })).toHaveLength(1);
  });

  it("detects interpreters by basename across paths, extensions and versions", async () => {
    for (const entry of [
      "/usr/local/bin/python3.12",
      "C:\\Program Files\\nodejs\\node.exe",
      "bash",
    ]) {
      try {
        await engine.setInjectionPolicy("secret://interp", {
          url_allowlist: [],
          command_allowlist: [entry],
          env_allowlist: [],
        });
        expect.fail("should throw");
      } catch (e) {
        expect((e as VaultError).code).toBe(ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED);
      }
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
    try {
      await engine.setInjectionPolicy("secret://interp", {
        url_allowlist: [],
        command_allowlist: ["python", "bash"],
        env_allowlist: [],
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INTERPRETER_NOT_ACKNOWLEDGED);
    }
    const refused = engine.queryAudit({
      eventType: AuditEventType.POLICY_INTERPRETER_REFUSED,
    });
    expect(refused).toHaveLength(1);
    expect(refused[0]?.detail?.interpreters).toEqual(["bash"]);
  });

  it("never gates non-interpreter commands", async () => {
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

describe("URL allowlist enforcement (HTTP)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "url-al",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("allows a request matching the allowlist", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    const res = await engine.useSecret("secret://url-al", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/ok`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
  });

  it("blocks a request not matching the allowlist", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/allowed/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    try {
      await engine.useSecret("secret://url-al", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/blocked`,
        injection: { type: "bearer" },
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_NOT_ALLOWED);
    }
  });

  it("audits a blocked URL with success=false", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/allowed/*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    try {
      await engine.useSecret("secret://url-al", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/blocked`,
        injection: { type: "bearer" },
      });
    } catch {
      // expected
    }
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denied = events.find((e) => e.detail?.error === "URL_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
  });

  it("re-validates every redirect hop against the allowlist (thesis §4.5.2)", async () => {
    await engine.setInjectionPolicy("secret://url-al", {
      url_allowlist: [`${baseUrl}/redirect-hop*`],
      command_allowlist: [],
      env_allowlist: [],
    });
    const before = requestCount;
    try {
      await engine.useSecret("secret://url-al", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/redirect-hop`,
        injection: { type: "bearer" },
        follow_redirects: "any",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_NOT_ALLOWED);
    }
    // The credential-bearing request never followed the redirect: only the
    // 302 itself was fetched, /target was not.
    expect(requestCount - before).toBe(1);
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denied = events.find((e) => e.detail?.error === "URL_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
  });
});

describe("use_secret action dispatch", () => {
  it("rejects an unknown action type at runtime (never-typed default arm)", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "dispatch",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    try {
      await engine.useSecret(
        "secret://dispatch",
        { type: "ftp" } as unknown as Parameters<VaultEngine["useSecret"]>[1],
      );
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
      expect((e as VaultError).message).toContain("Unsupported action type: ftp");
    }
  });
});

describe("response mode enforcement (HTTP)", () => {
  const secretValue = "rm-secret-value-2026";

  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "rm",
      type: "api_key",
      value: new Uint8Array(Buffer.from(secretValue)),
    });
  });

  it("defaults to filtered: body and headers returned, value redacted", async () => {
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.headers).toBeDefined();
    const body = JSON.parse(res.body ?? "{}") as Record<string, string>;
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });

  it("filtered redacts encoded echoes (base64, hex, percent)", async () => {
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/enc`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.body).toBeDefined();
    expect(res.body).not.toContain(Buffer.from(secretValue).toString("base64"));
    expect(res.body).not.toContain(Buffer.from(secretValue).toString("hex"));
    expect(res.body).toContain("[REDACTED]");
  });

  it("status_only policy strips body and headers", async () => {
    await engine.setInjectionPolicy("secret://rm", { response_mode: "status_only" });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.body).toBeUndefined();
    expect(res.headers).toBeUndefined();
  });

  it("status_only returns only allowlisted headers", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      response_mode: "status_only",
      response_header_allowlist: ["Content-Type"],
    });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.headers).toEqual({ "content-type": "application/json" });
    expect(res.body).toBeUndefined();
  });

  it("a per-invocation override may tighten the default floor", async () => {
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
      response_mode: "status_only",
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
    expect(res.body).toBeUndefined();
  });

  it("an equal-mode override is accepted", async () => {
    await engine.setInjectionPolicy("secret://rm", { response_mode: "status_only" });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
      response_mode: "status_only",
    });
    if (res.type !== "http") throw new Error("expected http result");
    expect(res.status).toBe(200);
  });

  it("rejects a loosening override without executing the request", async () => {
    await engine.setInjectionPolicy("secret://rm", { response_mode: "status_only" });
    const before = requestCount;
    try {
      await engine.useSecret("secret://rm", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/x`,
        injection: { type: "bearer" },
        response_mode: "full",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.RESPONSE_MODE_NOT_ALLOWED);
    }
    expect(requestCount).toBe(before);
    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denied = events.find((e) => e.detail?.error === "RESPONSE_MODE_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
    expect(denied?.detail?.requested_mode).toBe("full");
    expect(denied?.detail?.policy_mode).toBe("status_only");
  });

  it("rejects requesting full against the default filtered floor", async () => {
    try {
      await engine.useSecret("secret://rm", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/x`,
        injection: { type: "bearer" },
        response_mode: "full",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.RESPONSE_MODE_NOT_ALLOWED);
    }
  });

  it("full policy returns the raw echo unredacted", async () => {
    await engine.setInjectionPolicy("secret://rm", { response_mode: "full" });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
    });
    if (res.type !== "http") throw new Error("expected http result");
    const body = JSON.parse(res.body ?? "{}") as Record<string, string>;
    expect(body.authorization).toBe(`Bearer ${secretValue}`);
  });

  it("full policy may be tightened to filtered per invocation", async () => {
    await engine.setInjectionPolicy("secret://rm", { response_mode: "full" });
    const res = await engine.useSecret("secret://rm", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/x`,
      injection: { type: "bearer" },
      response_mode: "filtered",
    });
    if (res.type !== "http") throw new Error("expected http result");
    const body = JSON.parse(res.body ?? "{}") as Record<string, string>;
    expect(body.authorization).toBe("Bearer [REDACTED]");
  });

  it("checks the URL allowlist before the response mode", async () => {
    await engine.setInjectionPolicy("secret://rm", {
      url_allowlist: [`${baseUrl}/allowed/*`],
      response_mode: "status_only",
    });
    try {
      await engine.useSecret("secret://rm", {
        type: "http",
        method: "GET",
        url: `${baseUrl}/blocked`,
        injection: { type: "bearer" },
        response_mode: "full",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_NOT_ALLOWED);
    }
  });
});

describe("useSecret (process injection)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "proc",
      type: "api_key",
      value: new Uint8Array(Buffer.from("procsecret")),
    });
  });

  it("runs an allowlisted command with the secret injected as an env var", async () => {
    await engine.setInjectionPolicy(
      "secret://proc",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    const res = await engine.useSecret("secret://proc", {
      type: "process",
      command: process.execPath,
      args: ["-e", `process.stdout.write(process.env.TOKEN ? "SET" : "UNSET")`],
      env_var: "TOKEN",
    });
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.exit_code).toBe(0);
    expect(res.stdout).toBe("SET");
  });

  it("redacts the secret from process output", async () => {
    await engine.setInjectionPolicy(
      "secret://proc",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    const res = await engine.useSecret("secret://proc", {
      type: "process",
      command: process.execPath,
      args: ["-e", `process.stdout.write(process.env.TOKEN)`],
      env_var: "TOKEN",
    });
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.stdout).not.toContain("procsecret");
    expect(res.stdout).toContain("[REDACTED]");
  });

  it("denies a process command by default when no allowlist is set", async () => {
    try {
      await engine.useSecret("secret://proc", {
        type: "process",
        command: process.execPath,
        args: ["-e", `process.stdout.write("x")`],
        env_var: "TOKEN",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });
});

describe("useSecret (database) — engine dispatch", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "db",
      type: "api_key",
      value: new Uint8Array(Buffer.from("admin:dbpass")),
    });
  });

  it("rejects a host outside the host allowlist before connecting", async () => {
    await engine.setInjectionPolicy("secret://db", {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["db.internal:5432"],
    });
    try {
      await engine.useSecret("secret://db", {
        type: "database",
        engine: "postgresql",
        host: "8.8.8.8",
        database: "app",
        query: "SELECT 1",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.HOST_NOT_ALLOWED);
    }
    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .find((e) => e.detail?.error === "HOST_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
    expect(denied?.detail?.context).toBe("database");
  });

  it("blocks SSRF to a private database host", async () => {
    try {
      await engine.useSecret("secret://db", {
        type: "database",
        engine: "postgresql",
        host: "10.0.0.5",
        database: "app",
        query: "SELECT 1",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });
});

describe("useSecret (ssh) — engine dispatch", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "sshkey",
      type: "api_key",
      value: new Uint8Array(Buffer.from("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----")),
    });
  });

  it("denies by default when the host allowlist is empty", async () => {
    try {
      await engine.useSecret("secret://sshkey", {
        type: "ssh",
        host: "deploy.example.com",
        user: "deploy",
        command: "whoami",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.HOST_NOT_ALLOWED);
    }
  });

  it("requires pinned host keys once the host is allowlisted", async () => {
    await engine.setInjectionPolicy("secret://sshkey", {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["deploy.example.com"],
    });
    try {
      await engine.useSecret("secret://sshkey", {
        type: "ssh",
        host: "deploy.example.com",
        user: "deploy",
        command: "whoami",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSH_NOT_CONFIGURED);
    }
  });
});

describe("useSecret (git) — engine dispatch", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "gh",
      type: "api_key",
      value: new Uint8Array(Buffer.from("x-access-token:ghp_token")),
    });
  });

  it("rejects a forbidden transport before touching the command", async () => {
    try {
      await engine.useSecret("secret://gh", {
        type: "git",
        operation: "clone",
        repository: "ext::sh -c whoami",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.GIT_UNSUPPORTED_TRANSPORT);
    }
  });

  it("denies git by default when no command allowlist is set", async () => {
    try {
      await engine.useSecret("secret://gh", {
        type: "git",
        operation: "clone",
        repository: "https://github.com/user/repo.git",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });
});

const MCP_TEST_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "engine-test-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      content: [{ type: "text", text: process.env.DOWNSTREAM_TOKEN || "unset" }],
    }});
  }
});
`;

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
      url: "https://mcp.example.com/mcp",
    });
    expect(await engine.deleteMcpServerConfig("secret://mcp")).toBe(true);
    expect(await engine.getMcpServerConfig("secret://mcp")).toBeUndefined();
    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE });
    expect(events.find((e) => e.detail?.policy === "mcp_server")).toBeDefined();
  });

  it("returns false when deleting a nonexistent config", async () => {
    expect(await engine.deleteMcpServerConfig("secret://mcp")).toBe(false);
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
    expect(events.find((e) => e.detail?.policy === "connection")).toBeDefined();
  });

  it("returns false when deleting a nonexistent config", async () => {
    expect(await engine.deleteConnectionConfig("secret://conn")).toBe(false);
  });
});

describe("useSecret (MCP proxy)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "mcpuse",
      type: "api_key",
      value: new Uint8Array(Buffer.from("mcpusesecret")),
    });
  });

  it("rejects an mcp action when no server config is set", async () => {
    try {
      await engine.useSecret("secret://mcpuse", {
        type: "mcp",
        server: "github-mcp",
        tool: "echo",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.MCP_SERVER_NOT_CONFIGURED);
    }
  });

  it("forwards a tool call to a spawned stdio server with the credential injected", async () => {
    await engine.setInjectionPolicy(
      "secret://mcpuse",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });

    const res = await engine.useSecret("secret://mcpuse", {
      type: "mcp",
      server: "test-mcp",
      tool: "leak",
    });
    if (res.type !== "mcp") throw new Error("expected mcp result");
    // The downstream server echoed its env credential; the vault redacted it.
    const text = JSON.stringify(res.content);
    expect(text).not.toContain("mcpusesecret");
    expect(text).toContain("[REDACTED]");
  });

  it("fail-safe denies a stdio launch without a command allowlist", async () => {
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });
    try {
      await engine.useSecret("secret://mcpuse", {
        type: "mcp",
        server: "test-mcp",
        tool: "leak",
      });
      expect.fail("should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.COMMAND_NOT_ALLOWED);
    }
  });

  it("audits mcp.spawn on first use and secret.use with context=mcp", async () => {
    await engine.setInjectionPolicy(
      "secret://mcpuse",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });

    await engine.useSecret("secret://mcpuse", { type: "mcp", server: "test-mcp", tool: "leak" });
    await engine.useSecret("secret://mcpuse", { type: "mcp", server: "test-mcp", tool: "leak" });

    const spawns = engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    expect(spawns).toHaveLength(1);
    expect(spawns[0]?.detail?.server).toBe("test-mcp");

    const uses = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const mcpUses = uses.filter((e) => e.detail?.context === "mcp");
    expect(mcpUses).toHaveLength(2);
  });

  it("lock() terminates live downstream servers and audits mcp.terminate", async () => {
    await engine.setInjectionPolicy(
      "secret://mcpuse",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });
    await engine.useSecret("secret://mcpuse", { type: "mcp", server: "test-mcp", tool: "leak" });

    await engine.lock();

    // The terminate must have been audited before the keys were wiped.
    await engine.unlock("password");
    const terminates = engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("vault_lock");
  });
});

describe("policies", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "policy-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("grants and lists policies", async () => {
    const secretId = await engine.resolveSecretId("secret://policy-test");

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read", "use"],
      },
      "admin",
    );

    expect(policy.id).toBeTruthy();

    const policies = engine.listPolicies(secretId);
    expect(policies.length).toBe(1);
  });

  it("revokes a policy", async () => {
    const secretId = await engine.resolveSecretId("secret://policy-test");

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read"],
      },
      "admin",
    );

    engine.revokePolicy(policy.id);
    expect(engine.listPolicies(secretId).length).toBe(0);
  });
});

describe("JWT tokens", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates and verifies a token", () => {
    const token = engine.createToken("user-1", ["read", "use"]);
    const decoded = engine.verifyToken(token);

    expect(decoded.sub).toBe("user-1");
    expect(decoded.scope).toEqual(["read", "use"]);
  });

  it("carries secret-name patterns in the secrets claim (thesis §4.7)", () => {
    const token = engine.createToken("user-1", ["use"], 60_000, {
      secrets: ["db-*", "api-key"],
    });
    const decoded = engine.verifyToken(token);
    expect(decoded.secrets).toEqual(["db-*", "api-key"]);
  });

  it("rejects an invalid secret-name pattern at creation", () => {
    for (const pattern of ["db/*", "db prod", "", "[a]"]) {
      try {
        engine.createToken("user-1", ["use"], 60_000, { secrets: [pattern] });
        expect.fail("should throw");
      } catch (e) {
        expect((e as VaultError).code).toBe(ErrorCode.INVALID_SECRET_NAME);
      }
    }
  });

  it("rejects invalid token", () => {
    expect(() => engine.verifyToken("bad.token.here")).toThrow(VaultError);
  });

  it("revokes a token", () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);

    engine.revokeToken(decoded.jti);

    expect(() => engine.verifyToken(token)).toThrow("revoked");
  });

  it("revoked token persists across engine restart", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);
    engine.revokeToken(decoded.jti);
    await engine.lock();

    // Re-open engine, same DB
    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("password");

    expect(() => engine2.verifyToken(token)).toThrow("revoked");
    await engine2.destroy();
  });

  it("rejects token from different vault (vault_id mismatch)", async () => {
    const token = engine.createToken("user-1", ["read"]);
    await engine.destroy();

    // Create a second vault
    const tempDir2 = join(tempDir, "vault2");
    mkdirSync(tempDir2, { recursive: true });
    const engine2 = new VaultEngine({
      dbPath: join(tempDir2, "test.vault.db"),
      sessionPath: join(tempDir2, "session.json"),
    });
    await engine2.initVault("password");

    try {
      engine2.verifyToken(token);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
    await engine2.destroy();
  });

  it("rejects expired token", () => {
    // Create token with 0 TTL (immediately expired)
    const token = engine.createToken("user-1", ["read"], 0);

    try {
      engine.verifyToken(token);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.TOKEN_EXPIRED);
    }
  });

  it("caps token TTL at MAX_TOKEN_TTL_MS", () => {
    // Request 7 days — should be capped to 24h
    const token = engine.createToken("user-1", ["read"], 7 * 24 * 60 * 60 * 1000);
    const decoded = engine.verifyToken(token);
    const ttlSeconds = decoded.exp - decoded.iat;
    expect(ttlSeconds).toBeLessThanOrEqual(24 * 60 * 60);
  });

  it("revocation with explicit expiresAt uses that value", () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);

    engine.revokeToken(decoded.jti, decoded.exp);
    expect(() => engine.verifyToken(token)).toThrow("revoked");
  });
});

describe("JWT edge cases", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("rejects token with tampered signature", () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Flip last character of signature
    const sig = parts[2] as string;
    const tampered = `${parts[0]}.${parts[1]}.${sig.slice(0, -1)}${sig.endsWith("A") ? "B" : "A"}`;

    try {
      engine.verifyToken(tampered);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects token with tampered payload", () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Replace payload with a different one
    const fakePayload = Buffer.from(JSON.stringify({ sub: "hacker" })).toString("base64url");
    const tampered = `${parts[0]}.${fakePayload}.${parts[2]}`;

    try {
      engine.verifyToken(tampered);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects 2-part token", () => {
    try {
      engine.verifyToken("header.body");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects 4-part token", () => {
    try {
      engine.verifyToken("a.b.c.d");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects empty-segment token", () => {
    try {
      engine.verifyToken("..");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });
});

describe("audit trail", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("logs vault unlock event", () => {
    const events = engine.queryAudit({ eventType: AuditEventType.VAULT_UNLOCK });
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  it("logs secret creation", async () => {
    await engine.createSecret({
      name: "audit-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://audit-test");
  });

  it("logs getSecretValue with action: get_value", async () => {
    await engine.createSecret({
      name: "audit-getval",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.getSecretValue("secret://audit-getval");

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    const getValEvents = events.filter((e) => e.detail?.action === "get_value");
    expect(getValEvents.length).toBe(1);
    expect(getValEvents[0]?.detail?.handle).toBe("secret://audit-getval");
  });
});

describe("audit trail for failed useSecret", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "audit-use",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });
  });

  it("logs DNS failure with success=false", async () => {
    await engine.useSecret("secret://audit-use", {
      type: "http",
      method: "GET",
      url: "https://this-host-does-not-exist-xyz123.invalid/api",
      injection: { type: "bearer" },
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.error).toBe("DNS_RESOLUTION_FAILED");
  });

  it("logs successful request with success=true", async () => {
    await engine.useSecret("secret://audit-use", {
      type: "http",
      method: "GET",
      url: `${baseUrl}/test`,
      injection: { type: "bearer" },
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.method).toBe("GET");
    expect(last?.detail?.status).toBe(200);
  });

  it("logs connection refused with success=false", async () => {
    await engine.useSecret("secret://audit-use", {
      type: "http",
      method: "GET",
      url: "http://127.0.0.1:2/api",
      timeout_ms: 5000,
      injection: { type: "bearer" },
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.error).toBeDefined();
  });
});

describe("session loading", () => {
  it("loads session after restart", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "persist",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    // Simulate restart — destroy engine, create new one
    await engine.destroy();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);

    const list = engine2.listSecrets();
    expect(list.length).toBe(1);

    await engine2.destroy();
  });

  it("session restore preserves audit log decryptability", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "audit-persist",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    // Verify audit entries exist before restart
    const beforeEvents = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(beforeEvents.length).toBe(1);
    expect(beforeEvents[0]?.detail?.handle).toBe("secret://audit-persist");

    // Simulate restart
    await engine.destroy();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);

    // After session restore, audit entries should still be decryptable
    const afterEvents = engine2.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(afterEvents.length).toBe(1);
    expect(afterEvents[0]?.detail?.handle).toBe("secret://audit-persist");

    // Create a new audit entry to verify audit key works for new writes too
    await engine2.createSecret({
      name: "post-restart",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val2")),
    });
    const newEvents = engine2.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(newEvents.length).toBe(2);

    await engine2.destroy();
  });
});

describe("destroy() correctness", () => {
  it("sets state to SEALED after destroy", async () => {
    await engine.initVault("password");
    expect(engine.getState()).toBe(VaultState.UNLOCKED);

    await engine.destroy();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("rejects listSecrets after destroy", async () => {
    await engine.initVault("password");
    await engine.destroy();

    try {
      engine.listSecrets();
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });

  it("rejects createSecret after destroy", async () => {
    await engine.initVault("password");
    await engine.destroy();

    try {
      await engine.createSecret({
        name: "fail",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v")),
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });
});

describe("password change", () => {
  it("changes password and re-unlocks with new password", async () => {
    await engine.initVault("old-pass1");
    await engine.createSecret({
      name: "keep",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-val")),
    });

    await engine.changePassword("old-pass1", "new-pass1");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("new-pass1");

    const value = await engine2.getSecretValue("secret://keep");
    expect(Buffer.from(value).toString()).toBe("secret-val");

    await engine2.destroy();
  });

  it("rejects change with wrong old password", async () => {
    await engine.initVault("correct-pass");

    try {
      await engine.changePassword("wrong-pass", "new-pass1");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.ENCRYPTION_ERROR);
    }
  });

  it("old password no longer works after change", async () => {
    await engine.initVault("old-pass1");
    await engine.changePassword("old-pass1", "new-pass1");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    try {
      await engine2.unlock("old-pass1");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PASSWORD);
    }
    await engine2.destroy();
  });

  it("rejects weak new password on changePassword", async () => {
    await engine.initVault("password");

    try {
      await engine.changePassword("password", "short");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.WEAK_PASSWORD);
    }
  });
});

describe("lockout mechanism", () => {
  it("triggers lockout after 5 failed unlock attempts", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      const eng = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected INVALID_PASSWORD
      }
      await eng.destroy();
    }

    // 6th attempt should hit lockout
    const eng = new VaultEngine({ dbPath, sessionPath });
    try {
      await eng.unlock("wrong123");
      expect.fail("Should throw lockout");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.LOCKOUT_ACTIVE);
    }
    await eng.destroy();
  });

  it("lockout rejects even the correct password", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    for (let i = 0; i < 5; i++) {
      const eng = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng.destroy();
    }

    // Correct password during lockout should also fail
    const eng = new VaultEngine({ dbPath, sessionPath });
    try {
      await eng.unlock("correct1");
      expect.fail("Should throw lockout");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.LOCKOUT_ACTIVE);
    }
    await eng.destroy();
  });

  it("resets failed attempt counter on successful unlock", async () => {
    await engine.initVault("correct1");
    await engine.lock();

    // 4 failed attempts (just below threshold)
    for (let i = 0; i < 4; i++) {
      const eng = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng.destroy();
    }

    // Successful unlock resets counter
    const eng = new VaultEngine({ dbPath, sessionPath });
    await eng.unlock("correct1");
    await eng.lock();

    // 4 more failed attempts should NOT trigger lockout (counter was reset)
    for (let i = 0; i < 4; i++) {
      const eng2 = new VaultEngine({ dbPath, sessionPath });
      try {
        await eng2.unlock("wrong123");
      } catch {
        // Expected
      }
      await eng2.destroy();
    }

    // 5th attempt should still succeed (total 4 since reset)
    const eng3 = new VaultEngine({ dbPath, sessionPath });
    try {
      await eng3.unlock("correct1");
      expect(eng3.getState()).toBe(VaultState.UNLOCKED);
    } finally {
      await eng3.destroy();
    }
  });
});

describe("audit trail completeness", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("logs secret rotation", async () => {
    await engine.createSecret({
      name: "rot-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });

    await engine.rotateSecret("secret://rot-audit", new Uint8Array(Buffer.from("new")));

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_ROTATE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://rot-audit");
  });

  it("logs secret revocation", async () => {
    await engine.createSecret({
      name: "rev-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    await engine.revokeSecret("secret://rev-audit");

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_REVOKE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://rev-audit");
  });

  it("logs set_value on pending secret", async () => {
    await engine.createSecret({ name: "pending-audit", type: "api_key" });
    await engine.setSecretValue("secret://pending-audit", new Uint8Array(Buffer.from("val")));

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    const setValueEvents = events.filter((e) => e.detail?.action === "set_value");
    expect(setValueEvents.length).toBe(1);
    expect(setValueEvents[0]?.detail?.handle).toBe("secret://pending-audit");
  });

  it("logs vault lock", async () => {
    await engine.lock();

    // Need a new engine to query audit (current engine is sealed)
    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("password");

    const events = engine2.queryAudit({ eventType: AuditEventType.VAULT_LOCK });
    expect(events.length).toBe(1);

    await engine2.destroy();
  });

  it("logs password change", async () => {
    await engine.changePassword("password", "new-password");

    const events = engine.queryAudit({ eventType: AuditEventType.VAULT_PASSWORD_CHANGE });
    expect(events.length).toBe(1);
  });

  it("logs policy grant", async () => {
    await engine.createSecret({
      name: "pol-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secretId = await engine.resolveSecretId("secret://pol-audit");

    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
      "admin",
    );

    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_GRANT });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.principal).toBe("agent:agent-1");
  });

  it("logs policy revocation", async () => {
    await engine.createSecret({
      name: "pol-rev-audit",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secretId = await engine.resolveSecretId("secret://pol-rev-audit");

    const policy = engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "agent-1", permissions: ["read"] },
      "admin",
    );

    engine.revokePolicy(policy.id);

    const events = engine.queryAudit({ eventType: AuditEventType.POLICY_REVOKE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.policy_id).toBe(policy.id);
  });
});

describe("secrets through VaultEngine — additional coverage", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates a secret with injection config", async () => {
    const result = await engine.createSecret({
      name: "injected-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      injection: { type: "header", header_name: "X-Api-Key" },
    });

    expect(result.handle).toBe("secret://injected-key");
    expect(result.status).toBe("created");
  });

  it("lists secrets filtered by project", async () => {
    await engine.createSecret({
      name: "a",
      type: "api_key",
      project: "proj-a",
      value: new Uint8Array(Buffer.from("va")),
    });
    await engine.createSecret({
      name: "b",
      type: "api_key",
      project: "proj-b",
      value: new Uint8Array(Buffer.from("vb")),
    });
    await engine.createSecret({
      name: "c",
      type: "api_key",
      value: new Uint8Array(Buffer.from("vc")),
    });

    const projA = engine.listSecrets("proj-a");
    expect(projA.length).toBe(1);
    expect(projA[0]?.name).toBe("a");

    const all = engine.listSecrets();
    expect(all.length).toBe(3);
  });

  it("creates a pending secret and sets its value", async () => {
    await engine.createSecret({ name: "deferred", type: "api_key" });

    const infoBefore = await engine.getSecretInfo("secret://deferred");
    expect(infoBefore.status).toBe("pending");

    await engine.setSecretValue("secret://deferred", new Uint8Array(Buffer.from("set-later")));

    const infoAfter = await engine.getSecretInfo("secret://deferred");
    expect(infoAfter.status).toBe("active");

    const value = await engine.getSecretValue("secret://deferred");
    expect(Buffer.from(value).toString()).toBe("set-later");
  });
});

describe("lazy expiry in info/list", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("getSecretInfo returns expired status for past-expiry secret", async () => {
    await engine.createSecret({
      name: "exp-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000, // Already expired
    });

    const info = await engine.getSecretInfo("secret://exp-test");
    expect(info.status).toBe("expired");
  });

  it("listSecrets returns expired status for past-expiry secret", async () => {
    await engine.createSecret({
      name: "exp-list",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
      expiresAt: Date.now() - 1000,
    });

    const list = engine.listSecrets();
    const found = list.find((s) => s.name === "exp-list");
    expect(found?.status).toBe("expired");
  });
});

describe("double lock / double destroy edge cases", () => {
  it("lock on sealed vault does not throw", async () => {
    await engine.initVault("password");
    await engine.lock();

    // Second lock should not throw — it's already sealed, auditLogger is null
    await engine.lock();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("destroy is idempotent", async () => {
    await engine.initVault("password");
    await engine.destroy();
    await engine.destroy();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });
});

describe("session keystore protection", () => {
  class FakeKeystoreProtector implements SessionKeyProtector {
    readonly scheme = "dpapi" as const;

    async protect(key: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(Buffer.concat([Buffer.from("WRAP:"), Buffer.from(key)]));
    }

    async unprotect(blob: Uint8Array): Promise<Uint8Array> {
      const buf = Buffer.from(blob);
      if (!buf.subarray(0, 5).equals(Buffer.from("WRAP:"))) throw new Error("not a wrapped blob");
      return new Uint8Array(buf.subarray(5));
    }
  }

  it("shares a wrapped session across engines with the same protector", async () => {
    const engineA = new VaultEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    await engineA.initVault("password");

    const file = JSON.parse(readFileSync(sessionPath, "utf8")) as { key_protection?: string };
    expect(file.key_protection).toBe("dpapi");

    const engineB = new VaultEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    expect(await engineB.loadSession()).toBe(true);
    expect(engineB.getState()).toBe(VaultState.UNLOCKED);
    await engineB.destroy();
    await engineA.destroy();
  });

  it("fails to load when the engine's protector cannot handle the stored scheme", async () => {
    const engineA = new VaultEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    await engineA.initVault("password");

    // The default protector (none in tests) cannot unwrap the dpapi-tagged file.
    const engineB = new VaultEngine({ dbPath, sessionPath });
    expect(await engineB.loadSession()).toBe(false);
    expect(engineB.getState()).toBe(VaultState.SEALED);
    await engineB.destroy();
    await engineA.destroy();
  });

  it("fails to load when key_protection is stripped from a wrapped file", async () => {
    const engineA = new VaultEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    await engineA.initVault("password");

    const file = JSON.parse(readFileSync(sessionPath, "utf8")) as Record<string, unknown>;
    file["key_protection"] = "none";
    writeFileSync(sessionPath, JSON.stringify(file), "utf8");

    // The wrapped blob is now presented as a raw key — the KEK unwrap must fail.
    const engineB = new VaultEngine({
      dbPath,
      sessionPath,
      sessionKeyProtector: new FakeKeystoreProtector(),
    });
    expect(await engineB.loadSession()).toBe(false);
    await engineB.destroy();
    await engineA.destroy();
  });

  describe.runIf(process.platform === "win32")("DPAPI end-to-end (Windows)", () => {
    it("wraps the session key via DPAPI and shares it across engines", async () => {
      const engineA = new VaultEngine({
        dbPath,
        sessionPath,
        sessionKeyProtector: new DpapiSessionKeyProtector(),
      });
      await engineA.initVault("password");

      const file = JSON.parse(readFileSync(sessionPath, "utf8")) as {
        key_protection?: string;
        session_key?: string;
      };
      expect(file.key_protection).toBe("dpapi");
      // A DPAPI blob is far larger than the 32-byte raw key (44 base64 chars).
      expect((file.session_key ?? "").length).toBeGreaterThan(100);

      const engineB = new VaultEngine({
        dbPath,
        sessionPath,
        sessionKeyProtector: new DpapiSessionKeyProtector(),
      });
      expect(await engineB.loadSession()).toBe(true);
      expect(engineB.getState()).toBe(VaultState.UNLOCKED);
      await engineB.destroy();
      await engineA.destroy();
    });
  });
});
