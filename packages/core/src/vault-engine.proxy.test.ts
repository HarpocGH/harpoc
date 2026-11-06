import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, Permission } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { ProxyTarget } from "./vault-engine.js";
import { registerAgents, registryOf, retainDecryptedValues } from "./__fixtures__/engine-seams.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const PLAINTEXT = "ghp-proxy-credential-b2";
const HANDLE = "secret://gh";
const TARGET: ProxyTarget = { method: "GET", origin: "https://api.github.com", path: "/user" };
const CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

let tempDir: string;
let engine: VaultEngine;
let secretId: string;

function proxyCaller(id: string): CallerContext {
  return {
    principal_type: "agent",
    principal_id: id,
    interface: "proxy",
    remote_address: "127.0.0.1",
  };
}

function grant(principalId: string, permissions: Permission[]): void {
  registerAgents(engine, principalId);
  engine.grantPolicy({ secretId, principalType: "agent", principalId, permissions }, "test-admin");
}

function useRows(id?: string) {
  return engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId: id });
}

const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-proxy-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  await engine.createSecret({
    name: "gh",
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(PLAINTEXT)),
  });
  secretId = await engine.resolveSecretId(HANDLE);
  await engine.setInjectionPolicy(HANDLE, {
    url_allowlist: ["https://api.github.com/*"],
    proxy: true,
  });
  grant("alice", ["use"]);
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("resolveForProxy — the lease", () => {
  it("hands a granted caller on an opted-in, allowlisted target the value, and writes no row before complete", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);

    expect(Buffer.from(lease.value).equals(Buffer.from(PLAINTEXT))).toBe(true);
    expect("caPem" in lease).toBe(false);
    expect(useRows(secretId)).toHaveLength(0);
  });

  it("complete({ status, sanitized: true }) writes the request's one secret.use row — method, origin, path, the caller's columns", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    lease.complete({ status: 200, sanitized: true });

    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: true,
      secret_id: secretId,
      principal_type: "agent",
      principal_id: "alice",
      ip_address: "127.0.0.1",
    });
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://api.github.com",
      path: "/user",
      status: 200,
      sanitized: true,
      interface: "proxy",
    });
  });

  it("a clean response carries no sanitized key, and a second complete is a no-op", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    lease.complete({ status: 404, sanitized: false });
    lease.complete({ error: ErrorCode.PROXY_UPSTREAM_FAILED });

    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(true);
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://api.github.com",
      path: "/user",
      status: 404,
      interface: "proxy",
    });
  });

  it("complete({ error }) writes the failed row with the code and no status", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    lease.complete({ error: ErrorCode.PROXY_UPSTREAM_FAILED });

    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://api.github.com",
      path: "/user",
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
      interface: "proxy",
    });
  });

  it("hands over the handle's --http-ca pin, and the row says ca_pinned", async () => {
    await engine.setConnectionConfig(HANDLE, { http: { ca_pem: CA_PEM } });

    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    expect(lease.caPem).toBe(CA_PEM);
    lease.complete({ status: 200, sanitized: false });

    expect(useRows(secretId)[0]?.detail).toMatchObject({ status: 200, ca_pinned: true });
  });

  it("the engine wipes its own decrypted buffer on release; the lease holds a copy that complete() wipes", async () => {
    const retained = retainDecryptedValues(engine);

    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    expect(retained).toHaveLength(1);
    expect(retained[0]?.length).toBe(PLAINTEXT.length);
    expect(allZero(retained[0] as Uint8Array)).toBe(true);
    expect(lease.value).not.toBe(retained[0]);
    expect(Buffer.from(lease.value).equals(Buffer.from(PLAINTEXT))).toBe(true);

    lease.complete({ status: 200, sanitized: false });
    expect(allZero(lease.value)).toBe(true);
  });

  it("a lease still open when the vault locks is recorded VAULT_LOCKED with its value wiped; a later complete is a no-op", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    await engine.lock();
    expect(allZero(lease.value)).toBe(true);
    lease.complete({ status: 200, sanitized: false });

    await engine.unlock("password");
    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://api.github.com",
      path: "/user",
      error: ErrorCode.VAULT_LOCKED,
      interface: "proxy",
    });
  });

  it("a seal while the value is being decrypted refuses VAULT_LOCKED and wipes the value — no lease opens on a sealed engine", async () => {
    const manager = (engine as unknown as { secretManager: SecretManager }).secretManager;
    const decrypt = manager.getSecretValue.bind(manager);
    let decrypted: Uint8Array | undefined;
    manager.getSecretValue = async (...args: Parameters<SecretManager["getSecretValue"]>) => {
      decrypted = await decrypt(...args);
      await engine.lock();
      return decrypted;
    };

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET),
      ErrorCode.VAULT_LOCKED,
    );
    expect(allZero(decrypted as Uint8Array)).toBe(true);
    await engine.unlock("password");
    expect(useRows(secretId)).toHaveLength(0);
  });

  it("a stale lease's late complete after lock and unlock is a no-op (no slide)", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    await engine.lock();
    await engine.unlock("password");
    const rowsBefore = useRows(secretId).length;
    const slide = vi.spyOn(engine as unknown as { touchSession: () => void }, "touchSession");

    lease.complete({ status: 200, sanitized: false });

    expect(slide).not.toHaveBeenCalled();
    expect(useRows(secretId)).toHaveLength(rowsBefore);
  });

  it("a live lease's complete slides the session once", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET);
    const slide = vi.spyOn(engine as unknown as { touchSession: () => void }, "touchSession");

    lease.complete({ status: 200, sanitized: false });
    expect(slide).toHaveBeenCalledTimes(1);

    lease.complete({ status: 200, sanitized: false });
    expect(slide).toHaveBeenCalledTimes(1);
  });
});

describe("resolveForProxy — the refusals, each with its failed secret.use row", () => {
  it("refuses a secret without the proxy opt-in PROXY_PLACEHOLDER_DENIED, naming the origin, before any decrypt", async () => {
    await engine.setInjectionPolicy(HANDLE, { url_allowlist: ["https://api.github.com/*"] });
    const retained = retainDecryptedValues(engine);

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET),
      ErrorCode.PROXY_PLACEHOLDER_DENIED,
    );
    expect(err.message).toBe(
      "Placeholder refused for https://api.github.com: the secret is not enabled for the egress proxy (harpoc secret allow --proxy)",
    );
    expect(err.message).not.toContain(PLAINTEXT);
    expect(retained).toHaveLength(0);
    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ success: false, principal_id: "alice" });
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://api.github.com",
      path: "/user",
      error: ErrorCode.PROXY_PLACEHOLDER_DENIED,
      interface: "proxy",
    });
  });

  it("refuses an origin outside url_allowlist URL_NOT_ALLOWED, naming the origin alone, before any decrypt", async () => {
    const retained = retainDecryptedValues(engine);
    const target = { method: "POST", origin: "https://evil.example.com", path: "/collect" };

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), target),
      ErrorCode.URL_NOT_ALLOWED,
    );
    expect(err.message).toBe("URL not in secret allowlist: https://evil.example.com");
    expect(err.message).not.toContain(PLAINTEXT);
    expect(retained).toHaveLength(0);
    expect(useRows(secretId)[0]?.detail).toEqual({
      context: "proxy",
      method: "POST",
      origin: "https://evil.example.com",
      path: "/collect",
      error: ErrorCode.URL_NOT_ALLOWED,
      interface: "proxy",
    });
  });

  it("matches the allowlist on origin and path — a path outside the pattern is refused like a foreign origin", async () => {
    await engine.setInjectionPolicy(HANDLE, {
      url_allowlist: ["https://api.github.com/repos/*"],
      proxy: true,
    });

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET),
      ErrorCode.URL_NOT_ALLOWED,
    );
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), {
      method: "GET",
      origin: "https://api.github.com",
      path: "/repos/o/r",
    });
    lease.complete({ status: 200, sanitized: false });
    expect(useRows(secretId).map((row) => row.success)).toEqual([true, false]);
  });

  it("tells a caller without the use grant SECRET_NOT_FOUND (R5); its row keeps ACCESS_DENIED with the real id and the live child ends (E73)", async () => {
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("mallory"), TARGET),
      ErrorCode.SECRET_NOT_FOUND,
    );
    expect(err.message).not.toContain(PLAINTEXT);
    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ success: false, secret_id: secretId, principal_id: "mallory" });
    expect(rows[0]?.detail).toEqual({
      handle: HANDLE,
      context: "proxy",
      method: "GET",
      origin: "https://api.github.com",
      path: "/user",
      required_permission: "use",
      error: ErrorCode.ACCESS_DENIED,
      interface: "proxy",
    });
    expect(terminate).toHaveBeenCalledWith(secretId, "use_denied", expect.anything());
  });

  it("tells a caller holding read but not use ACCESS_DENIED", async () => {
    grant("reader", ["read"]);

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("reader"), TARGET),
      ErrorCode.ACCESS_DENIED,
    );
    expect(err.message).toBe("Access denied: Principal lacks 'use' permission on this secret");
  });

  it("refuses an unknown handle SECRET_NOT_FOUND with a denied row that has no secret id", async () => {
    await expectVaultError(
      () => engine.resolveForProxy("secret://nope", proxyCaller("alice"), TARGET),
      ErrorCode.SECRET_NOT_FOUND,
    );
    const rows = useRows().filter((row) => row.detail?.["handle"] === "secret://nope");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ success: false, secret_id: null, principal_id: "alice" });
    expect(rows[0]?.detail).toEqual({
      handle: "secret://nope",
      context: "proxy",
      method: "GET",
      origin: "https://api.github.com",
      path: "/user",
      error: ErrorCode.SECRET_NOT_FOUND,
      interface: "proxy",
    });
  });

  it("refuses an expired secret SECRET_EXPIRED ahead of the opt-in and the allowlist (assertUsable first)", async () => {
    await engine.setInjectionPolicy(HANDLE, {});
    (engine as unknown as { store: SqliteStore }).store.updateSecret(secretId, {
      expires_at: Date.now() - 1000,
    });
    const terminate = vi.spyOn(registryOf(engine), "terminate");

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), TARGET),
      ErrorCode.SECRET_EXPIRED,
    );
    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toMatchObject({ context: "proxy", error: ErrorCode.SECRET_EXPIRED });
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE, secretId })).toHaveLength(
      1,
    );
    expect(terminate).toHaveBeenCalledWith(secretId, "secret_unusable", expect.anything());
  });

  it("refuses a caller-less call and a target that is not an origin and a query-less path INVALID_INPUT, unaudited", async () => {
    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, undefined as unknown as CallerContext, TARGET),
      ErrorCode.INVALID_INPUT,
    );
    for (const target of [
      { ...TARGET, path: "/user?token=harpoc:gh" },
      { ...TARGET, path: "/user#frag" },
      { ...TARGET, path: "@evil.example.com/x" },
      { ...TARGET, path: "/a/../user" },
      { ...TARGET, origin: "https://api.github.com/" },
      { ...TARGET, origin: "https://u:p@api.github.com" },
      { ...TARGET, origin: "ftp://api.github.com" },
      { ...TARGET, method: "GET /x" },
    ]) {
      await expectVaultError(
        () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), target),
        ErrorCode.INVALID_INPUT,
      );
    }
    expect(useRows()).toHaveLength(0);
  });
});
