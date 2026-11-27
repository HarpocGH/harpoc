import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccessPolicy, CallerContext, Permission, VaultApiToken } from "@harpoc/shared";
import {
  AuditEventType,
  callerFromToken,
  ErrorCode,
  proxySocketCaller,
  SecretType,
} from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { ProxyTarget } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";
import type { SecretManager } from "./secrets/secret-manager.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const PLAINTEXT = "ghp-proxy-trusted-credential-t2";
const NAME = "gh";
const HANDLE = `secret://${NAME}`;
const AGENT = "alice";
const UNREGISTERED = "ghost";
const TARGET: ProxyTarget = { method: "GET", origin: "https://api.github.com", path: "/user" };
const REQUEST = { context: "proxy", ...TARGET };
const NOT_TRUSTED = "assertProxyConsumer needs a trusted socket's caller";

let tempDir: string;
let engine: VaultEngine;
let secretId: string;
let policy: AccessPolicy;

function grant(principalId: string, permissions: Permission[]): AccessPolicy {
  registerAgents(engine, principalId);
  return engine.grantPolicy(
    { secretId, principalType: "agent", principalId, permissions },
    "test-admin",
  );
}

function useRows(id?: string) {
  return engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId: id });
}

function trailPrincipals(): (string | null)[] {
  return engine.queryAudit({}).map((row) => row.principal_id);
}

function tokenCaller(
  principalId: string,
  scope: VaultApiToken["scope"],
  secrets?: string[],
): CallerContext {
  return callerFromToken(
    {
      sub: principalId,
      vault_id: "vault-1",
      scope,
      iat: 0,
      exp: 2_000_000_000,
      jti: "jti-1",
      principal_type: "agent",
      ...(secrets === undefined ? {} : { secrets }),
    },
    "proxy",
    "127.0.0.1",
  );
}

const withProject = (): CallerContext => ({ ...proxySocketCaller(AGENT, ["*"]), project: "p" });

const withAdminFlag = (): CallerContext => ({
  ...tokenCaller(AGENT, ["admin"]),
  ...proxySocketCaller(AGENT, ["*"]),
});

const ONE_CONDITION_FAILS: { label: string; caller: () => CallerContext }[] = [
  {
    label: "on another interface",
    caller: () => ({ ...proxySocketCaller(AGENT, [NAME]), interface: "mcp" }),
  },
  {
    label: "of user type",
    caller: () => ({ ...proxySocketCaller(AGENT, [NAME]), principal_type: "user" }),
  },
  {
    label: "whose tokenless mark is not true",
    caller: () => ({ ...proxySocketCaller(AGENT, [NAME]), tokenless: false as unknown as true }),
  },
];

const secretManagerOf = (): SecretManager =>
  (engine as unknown as { secretManager: SecretManager }).secretManager;

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-proxy-trusted-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  await engine.createSecret({
    name: NAME,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(PLAINTEXT)),
  });
  secretId = await engine.resolveSecretId(HANDLE);
  await engine.setInjectionPolicy(HANDLE, {
    url_allowlist: ["https://api.github.com/*"],
    proxy: true,
  });
  policy = grant(AGENT, ["use"]);
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("resolveForProxy — a trusted socket's caller", () => {
  it("a registered, active, granted agent opens a lease; its completed row says interface proxy and tokenless", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxySocketCaller(AGENT, [NAME]), TARGET);
    expect(Buffer.from(lease.value).equals(Buffer.from(PLAINTEXT))).toBe(true);
    lease.complete({ status: 200, sanitized: false });

    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: true,
      secret_id: secretId,
      principal_type: "agent",
      principal_id: AGENT,
    });
    expect(rows[0]?.detail).toEqual({
      ...REQUEST,
      status: 200,
      interface: "proxy",
      tokenless: true,
    });
  });

  it("a lease whose body its upstream cut, completed with a status and a code, writes one failed row carrying both and the tokenless mark", async () => {
    const lease = await engine.resolveForProxy(HANDLE, proxySocketCaller(AGENT, [NAME]), TARGET);
    lease.complete({ status: 200, error: ErrorCode.PROXY_UPSTREAM_FAILED, sanitized: false });

    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: false,
      secret_id: secretId,
      principal_type: "agent",
      principal_id: AGENT,
    });
    expect(rows[0]?.detail).toEqual({
      ...REQUEST,
      status: 200,
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
      interface: "proxy",
      tokenless: true,
    });
  });

  it("the same agent deactivated is refused AGENT_INACTIVE with one failed secret.use row marked tokenless, before any decrypt", async () => {
    engine.deactivateAgent(AGENT);
    const decrypt = vi.spyOn(secretManagerOf(), "getSecretValue");

    const err = await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxySocketCaller(AGENT, [NAME]), TARGET),
      ErrorCode.AGENT_INACTIVE,
    );
    expect(err.message).toBe(
      `Agent "${AGENT}" is deactivated. Reactivate it with: harpoc agent activate ${AGENT}`,
    );
    expect(decrypt).not.toHaveBeenCalled();
    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: false,
      secret_id: null,
      principal_type: "agent",
      principal_id: AGENT,
    });
    expect(rows[0]?.detail).toEqual({
      handle: HANDLE,
      ...REQUEST,
      error: ErrorCode.AGENT_INACTIVE,
      interface: "proxy",
      tokenless: true,
    });
  });

  it("an unregistered name is refused AGENT_NOT_FOUND with one failed secret.use row and no secret id", async () => {
    const decrypt = vi.spyOn(secretManagerOf(), "getSecretValue");

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxySocketCaller(UNREGISTERED, [NAME]), TARGET),
      ErrorCode.AGENT_NOT_FOUND,
    );
    expect(decrypt).not.toHaveBeenCalled();
    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: false,
      secret_id: null,
      principal_type: "agent",
      principal_id: UNREGISTERED,
    });
    expect(rows[0]?.detail).toEqual({
      handle: HANDLE,
      ...REQUEST,
      error: ErrorCode.AGENT_NOT_FOUND,
      interface: "proxy",
      tokenless: true,
    });
  });

  it("a trusted caller carrying a project, or the admin flag of a token caller, is refused INVALID_INPUT without a row", async () => {
    const adminFlagged = withAdminFlag();
    expect("admin_scope" in adminFlagged).toBe(true);
    const decrypt = vi.spyOn(secretManagerOf(), "getSecretValue");

    for (const caller of [withProject(), adminFlagged]) {
      await expectVaultError(
        () => engine.resolveForProxy(HANDLE, caller, TARGET),
        ErrorCode.INVALID_INPUT,
      );
    }
    expect(decrypt).not.toHaveBeenCalled();
    expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
  });

  it("a trusted caller holding no secret-name pattern is refused INVALID_INPUT without a row", async () => {
    const decrypt = vi.spyOn(secretManagerOf(), "getSecretValue");

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, proxySocketCaller(AGENT, []), TARGET),
      ErrorCode.INVALID_INPUT,
    );
    expect(decrypt).not.toHaveBeenCalled();
    expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
  });

  it.each(ONE_CONDITION_FAILS)(
    "a tokenless caller $label is refused INVALID_INPUT without a row",
    async ({ caller }) => {
      const decrypt = vi.spyOn(secretManagerOf(), "getSecretValue");

      const err = await expectVaultError(
        () => engine.resolveForProxy(HANDLE, caller(), TARGET),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe("resolveForProxy needs a trusted socket's caller");
      expect(decrypt).not.toHaveBeenCalled();
      expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
    },
  );

  it("a token caller of a deactivated agent is served as today, its row without the tokenless mark", async () => {
    engine.deactivateAgent(AGENT);

    const lease = await engine.resolveForProxy(HANDLE, tokenCaller(AGENT, ["use"]), TARGET);
    lease.complete({ status: 200, sanitized: false });

    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: true,
      secret_id: secretId,
      principal_id: AGENT,
      ip_address: "127.0.0.1",
    });
    expect(rows[0]?.detail).toEqual({ ...REQUEST, status: 200, interface: "proxy" });
  });

  it("a grant revoked after the socket is trusted is refused by the use ladder, its failed row marked tokenless", async () => {
    const caller = proxySocketCaller(AGENT, [NAME]);
    engine.assertProxyConsumer(caller);
    engine.revokePolicy(policy.id);

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, caller, TARGET),
      ErrorCode.SECRET_NOT_FOUND,
    );
    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      success: false,
      secret_id: secretId,
      principal_type: "agent",
      principal_id: AGENT,
    });
    expect(rows[0]?.detail).toEqual({
      handle: HANDLE,
      ...REQUEST,
      required_permission: "use",
      error: ErrorCode.ACCESS_DENIED,
      interface: "proxy",
      tokenless: true,
    });
  });
});

describe("VaultEngine.assertProxyConsumer", () => {
  it("passes a registered, active agent's trusted caller, writing no row", () => {
    engine.assertProxyConsumer(proxySocketCaller(AGENT, [NAME]));

    expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
  });

  it("refuses a deactivated agent AGENT_INACTIVE, writing no row", async () => {
    engine.deactivateAgent(AGENT);

    await expectVaultError(
      () => engine.assertProxyConsumer(proxySocketCaller(AGENT, [NAME])),
      ErrorCode.AGENT_INACTIVE,
    );
    expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
  });

  it("refuses an unregistered agent AGENT_NOT_FOUND, writing no row", async () => {
    const err = await expectVaultError(
      () => engine.assertProxyConsumer(proxySocketCaller(UNREGISTERED, [NAME])),
      ErrorCode.AGENT_NOT_FOUND,
    );
    expect(err.message).toBe(
      `Agent not registered: "${UNREGISTERED}". Register it with: harpoc agent register ${UNREGISTERED}`,
    );
    expectAbsent(trailPrincipals(), UNREGISTERED, "the trail's principals");
  });

  it("refuses on a sealed engine VAULT_LOCKED", async () => {
    await engine.lock();

    await expectVaultError(
      () => engine.assertProxyConsumer(proxySocketCaller(AGENT, [NAME])),
      ErrorCode.VAULT_LOCKED,
    );
  });

  it("refuses a token caller whose token claims the secret-name pattern INVALID_INPUT, writing no row", async () => {
    const caller = tokenCaller(AGENT, ["use"], [NAME]);
    expect(caller.secrets).toEqual([NAME]);

    const err = await expectVaultError(
      () => engine.assertProxyConsumer(caller),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(NOT_TRUSTED);
    expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
  });

  it("refuses a trusted caller holding no secret-name pattern INVALID_INPUT, writing no row", async () => {
    const err = await expectVaultError(
      () => engine.assertProxyConsumer(proxySocketCaller(AGENT, [])),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe(NOT_TRUSTED);
    expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
  });

  it("refuses a trusted caller carrying a project, or the admin flag of a token caller, INVALID_INPUT, writing no row", async () => {
    const adminFlagged = withAdminFlag();
    expect("admin_scope" in adminFlagged).toBe(true);

    for (const caller of [withProject(), adminFlagged]) {
      const err = await expectVaultError(
        () => engine.assertProxyConsumer(caller),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(NOT_TRUSTED);
    }
    expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
  });

  it.each(ONE_CONDITION_FAILS)(
    "refuses a tokenless caller $label INVALID_INPUT, writing no row",
    async ({ caller }) => {
      const err = await expectVaultError(
        () => engine.assertProxyConsumer(caller()),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(NOT_TRUSTED);
      expectAbsent(trailPrincipals(), AGENT, "the trail's principals");
    },
  );
});
