import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, Permission } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { ProxyTarget } from "./vault-engine.js";
import { registerAgents, retainDecryptedValues } from "./__fixtures__/engine-seams.js";
import type { SecretManager } from "./secrets/secret-manager.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const PLAINTEXT = "ghp-proxy-credential-plain";
const HANDLE = "secret://gh";
const PLAIN: ProxyTarget = {
  method: "GET",
  origin: "https://127.0.0.1:9000",
  path: "/x",
  plainOrigin: "http://127.0.0.1:9000",
};
const PLAIN_ROW = {
  context: "proxy",
  method: "GET",
  origin: "http://127.0.0.1:9000",
  path: "/x",
  plain_http: true,
  interface: "proxy",
};
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

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-proxy-plain-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
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
    url_allowlist: ["http://127.0.0.1:9000/*"],
    proxy: true,
  });
  grant("alice", ["use"]);
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("resolveForProxy — the plain reading of a loopback literal", () => {
  it("an http:// entry naming the literal serves the plain reading", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN);

    expect(Buffer.from(lease.value).equals(Buffer.from(PLAINTEXT))).toBe(true);
    expect(lease.plainHttp).toBe(true);
    expect("caPem" in lease).toBe(false);
    expect(useRows(secretId)).toHaveLength(0);
  });

  it("the success row names the http origin with plain_http and no ca_pinned", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN);
    lease.complete({ status: 200, sanitized: false });

    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(true);
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "http://127.0.0.1:9000",
      path: "/x",
      status: 200,
      plain_http: true,
      interface: "proxy",
    });
  });

  it("a failure through complete and the lock's drain keep both marks", async () => {
    const failed = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN);
    failed.complete({ error: ErrorCode.PROXY_UPSTREAM_FAILED });
    await engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN);
    await engine.lock();

    await engine.unlock("password");
    const rows = useRows(secretId);
    expect(rows.map((row) => row.success)).toEqual([false, false]);
    expect(rows.map((row) => row.detail)).toEqual([
      { ...PLAIN_ROW, error: ErrorCode.VAULT_LOCKED },
      { ...PLAIN_ROW, error: ErrorCode.PROXY_UPSTREAM_FAILED },
    ]);
  });

  it("a decrypt that fails after the judgement leaves its row on the plain reading", async () => {
    const manager = (engine as unknown as { secretManager: SecretManager }).secretManager;
    const spy = vi.spyOn(manager, "getSecretValue").mockRejectedValue(VaultError.vaultCorrupted());
    try {
      await expectVaultError(
        () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN),
        ErrorCode.VAULT_CORRUPTED,
      );
    } finally {
      spy.mockRestore();
    }

    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toEqual({
      handle: HANDLE,
      ...PLAIN_ROW,
      error: ErrorCode.VAULT_CORRUPTED,
    });
  });

  it("[::1], and port 80 without a port", async () => {
    for (const [entry, origin, plainOrigin] of [
      ["http://[::1]:9000/*", "https://[::1]:9000", "http://[::1]:9000"],
      ["http://127.0.0.1/*", "https://127.0.0.1", "http://127.0.0.1"],
    ] as const) {
      await engine.setInjectionPolicy(HANDLE, { url_allowlist: [entry], proxy: true });

      const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), {
        method: "GET",
        origin,
        path: "/x",
        plainOrigin,
      });
      expect(lease.plainHttp).toBe(true);
      lease.complete({ status: 200, sanitized: false });

      expect(useRows(secretId)[0]?.detail).toEqual({
        ...PLAIN_ROW,
        origin: plainOrigin,
        status: 200,
      });
    }
  });

  it("two ports, two schemes", async () => {
    await engine.setInjectionPolicy(HANDLE, {
      url_allowlist: ["https://127.0.0.1:8443/*", "http://127.0.0.1:9000/*"],
      proxy: true,
    });
    const tls: ProxyTarget = {
      method: "GET",
      origin: "https://127.0.0.1:8443",
      path: "/x",
      plainOrigin: "http://127.0.0.1:8443",
    };
    const tlsRow = {
      context: "proxy",
      method: "GET",
      origin: "https://127.0.0.1:8443",
      path: "/x",
      interface: "proxy",
    };

    const onTls = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), tls);
    expect("plainHttp" in onTls).toBe(false);
    onTls.complete({ status: 200, sanitized: false });
    expect(useRows(secretId)[0]?.detail).toEqual({ ...tlsRow, status: 200 });

    const plain = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN);
    expect(plain.plainHttp).toBe(true);
    plain.complete({ status: 200, sanitized: false });
    expect(useRows(secretId)[0]?.detail).toEqual({ ...PLAIN_ROW, status: 200 });

    await engine.setConnectionConfig(HANDLE, { http: { ca_pem: CA_PEM } });

    const pinned = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), tls);
    expect(pinned.caPem).toBe(CA_PEM);
    pinned.complete({ status: 200, sanitized: false });
    expect(useRows(secretId)[0]?.detail).toEqual({ ...tlsRow, status: 200, ca_pinned: true });

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN),
      ErrorCode.URL_NOT_ALLOWED,
    );
    expect(err.message).toBe("URL not in secret allowlist: https://127.0.0.1:9000");
    expect(useRows(secretId)[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://127.0.0.1:9000",
      path: "/x",
      error: ErrorCode.URL_NOT_ALLOWED,
      interface: "proxy",
    });

    const rows = useRows(secretId);
    expect(rows).toHaveLength(4);
    for (const row of rows) {
      const detail = row.detail ?? {};
      expect("plain_http" in detail && "ca_pinned" in detail).toBe(false);
    }
  });

  it("an https:// entry beside the http:// entry, both matching, keeps the request on TLS", async () => {
    await engine.setInjectionPolicy(HANDLE, {
      url_allowlist: ["https://127.0.0.1:9000/*", "http://127.0.0.1:9000/*"],
      proxy: true,
    });

    const lease = await engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN);
    expect("plainHttp" in lease).toBe(false);
    lease.complete({ status: 200, sanitized: false });

    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(true);
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://127.0.0.1:9000",
      path: "/x",
      status: 200,
      interface: "proxy",
    });
  });

  it("an http: origin is refused INVALID_INPUT before anything is judged, even where an http:// entry names it", async () => {
    const retained = retainDecryptedValues(engine);
    const onHttp: ProxyTarget = { method: "GET", origin: "http://127.0.0.1:9000", path: "/x" };

    for (const target of [onHttp, { ...onHttp, plainOrigin: "http://127.0.0.1:9000" }]) {
      const err = await expectVaultError(
        () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), target),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(
        "Invalid proxy target: an http(s) origin and a path without query or fragment",
      );
    }
    expect(useRows()).toHaveLength(0);
    expect(retained).toHaveLength(0);
  });
});

describe("resolveForProxy — a plain reading that is not served is refused as today", () => {
  const onHost = (host: string): ProxyTarget => ({
    method: "GET",
    origin: `https://${host}:9000`,
    path: "/x",
    plainOrigin: `http://${host}:9000`,
  });

  it.each<[string, string[], ProxyTarget, boolean]>([
    ["no http:// entry", ["https://api.github.com/*"], PLAIN, false],
    ["a path mismatch", ["http://127.0.0.1:9000/api/*"], PLAIN, false],
    ["a *. host entry that matches by suffix", ["http://*.0.0.1:9000/*"], PLAIN, false],
    [
      "an https:// entry for the authority, whatever its path",
      ["http://127.0.0.1:9000/*", "https://127.0.0.1:9000/none/*"],
      PLAIN,
      false,
    ],
    ["a CA pinned", ["http://127.0.0.1:9000/*"], PLAIN, true],
    [
      "an entry spelled with :80 for the port-80 target",
      ["http://127.0.0.1:80/*"],
      {
        method: "GET",
        origin: "https://127.0.0.1",
        path: "/x",
        plainOrigin: "http://127.0.0.1",
      },
      false,
    ],
    ["localhost", ["http://localhost:9000/*"], onHost("localhost"), false],
    ["127.0.0.2", ["http://127.0.0.2:9000/*"], onHost("127.0.0.2"), false],
    ["[::ffff:7f00:1]", ["http://[::ffff:7f00:1]:9000/*"], onHost("[::ffff:7f00:1]"), false],
    [
      "a plainOrigin with a trailing slash",
      ["http://127.0.0.1:9000/*"],
      { ...PLAIN, plainOrigin: "http://127.0.0.1:9000/" },
      false,
    ],
    [
      "a plainOrigin with userinfo",
      ["http://127.0.0.1:9000/*"],
      { ...PLAIN, plainOrigin: "http://u:p@127.0.0.1:9000" },
      false,
    ],
    [
      "a plainOrigin beside another host's origin",
      ["http://127.0.0.1:9000/*"],
      { ...PLAIN, origin: "https://api.github.com" },
      false,
    ],
  ])("%s", async (_title, urlAllowlist, target, caPinned) => {
    await engine.setInjectionPolicy(HANDLE, { url_allowlist: urlAllowlist, proxy: true });
    if (caPinned) await engine.setConnectionConfig(HANDLE, { http: { ca_pem: CA_PEM } });
    const retained = retainDecryptedValues(engine);

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), target),
      ErrorCode.URL_NOT_ALLOWED,
    );
    expect(err.message).toBe(`URL not in secret allowlist: ${target.origin}`);
    expect(retained).toHaveLength(0);
    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: target.origin,
      path: "/x",
      error: ErrorCode.URL_NOT_ALLOWED,
      interface: "proxy",
    });
  });
});

describe("resolveForProxy — a connection config that cannot be read", () => {
  const TLS_REFUSAL = {
    context: "proxy",
    method: "GET",
    origin: "https://127.0.0.1:9000",
    path: "/x",
    error: ErrorCode.URL_NOT_ALLOWED,
    interface: "proxy",
  };

  function unreadableConfig() {
    return vi
      .spyOn(
        engine as unknown as { loadConnectionConfig: (...args: unknown[]) => unknown },
        "loadConnectionConfig",
      )
      .mockImplementation(() => {
        throw VaultError.vaultCorrupted();
      });
  }

  it("a candidate whose connection config cannot be read is refused on its TLS reading", async () => {
    const retained = retainDecryptedValues(engine);
    const loader = unreadableConfig();
    try {
      const err = await expectVaultError(
        () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN),
        ErrorCode.URL_NOT_ALLOWED,
      );
      expect(err.message).toBe("URL not in secret allowlist: https://127.0.0.1:9000");
      expect(loader).toHaveBeenCalledTimes(1);
    } finally {
      loader.mockRestore();
    }

    expect(retained).toHaveLength(0);
    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toEqual(TLS_REFUSAL);
  });

  it("a request that is no candidate never reads the connection config before its refusal", async () => {
    await engine.setInjectionPolicy(HANDLE, {
      url_allowlist: ["https://api.github.com/*"],
      proxy: true,
    });
    const loader = unreadableConfig();
    try {
      const err = await expectVaultError(
        () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN),
        ErrorCode.URL_NOT_ALLOWED,
      );
      expect(err.message).toBe("URL not in secret allowlist: https://127.0.0.1:9000");
      expect(loader).not.toHaveBeenCalled();
    } finally {
      loader.mockRestore();
    }

    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toEqual(TLS_REFUSAL);
  });
});

describe("resolveForProxy — the opt-in refusal precedes the plain judgement", () => {
  it("the opt-in refusal keeps the TLS reading", async () => {
    await engine.setInjectionPolicy(HANDLE, {
      url_allowlist: ["http://127.0.0.1:9000/*"],
      proxy: false,
    });

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxyCaller("alice"), PLAIN),
      ErrorCode.PROXY_PLACEHOLDER_DENIED,
    );
    expect(err.message).toBe(
      "Placeholder refused for https://127.0.0.1:9000: the secret is not enabled for the egress proxy (harpoc secret allow --proxy)",
    );
    const rows = useRows(secretId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ success: false, principal_id: "alice" });
    expect(rows[0]?.detail).toEqual({
      context: "proxy",
      method: "GET",
      origin: "https://127.0.0.1:9000",
      path: "/x",
      error: ErrorCode.PROXY_PLACEHOLDER_DENIED,
      interface: "proxy",
    });
  });
});
