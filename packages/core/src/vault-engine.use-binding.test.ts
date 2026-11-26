import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Mock } from "vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, UseSecretAction } from "@harpoc/shared";
import { agentSocketCaller, AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { registerAgents, retainDecryptedValues } from "./__fixtures__/engine-seams.js";
import {
  buildUserauthRequest,
  fixtureKnownHostsLine,
  fixturePublicBlob,
  readSshFixture,
} from "./injection/__fixtures__/agent-client.js";
import type { AgentSignRequest } from "./injection/ssh-agent/agent-connection.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { ProxyTarget } from "./vault-engine.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const VALUE = "judged-credential-value";
const OTHER_VALUE = "other-credential-value";
const HANDLE = "secret://k";
const KEY_NAME = "deploy-key";
const KEY_HANDLE = `secret://${KEY_NAME}`;
const ED_KEY = fixturePublicBlob("ed25519_openssh");
const EC_KEY = fixturePublicBlob("ecdsa256_openssh");
const HOST_KEY = fixturePublicBlob("ecdsa384_openssh");
const SESSION = Buffer.alloc(32, 0x5a);
const CONSUMER = "ci-bot";
const HTTP_GET: UseSecretAction = {
  type: "http",
  method: "GET",
  url: "https://api.example.com/user",
  injection: { type: "bearer" },
};
const TARGET: ProxyTarget = { method: "GET", origin: "https://api.example.com", path: "/user" };
const PROXY_CALLER: CallerContext = {
  principal_type: "agent",
  principal_id: "alice",
  interface: "proxy",
  remote_address: "127.0.0.1",
};

type Inject = (...args: unknown[]) => Promise<unknown>;

let tempDir: string;
let engine: VaultEngine;
let injector: Mock<Inject>;

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-use-binding-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  injector = vi.fn<Inject>(() => Promise.resolve({ type: "http", status: 200 }));
  (engine as unknown as { httpInjector: { executeWithSecret: Inject } }).httpInjector = {
    executeWithSecret: injector,
  };
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function storeSecret(name: string, value: string): Promise<string> {
  await engine.createSecret({
    name,
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(value)),
  });
  return engine.resolveSecretId(`secret://${name}`);
}

/** `secret://k`, allowlisted for api.example.com, opted in to the proxy, `use` granted to alice. */
async function storeAllowlisted(): Promise<string> {
  const id = await storeSecret("k", VALUE);
  await engine.setInjectionPolicy(HANDLE, {
    url_allowlist: ["https://api.example.com/*"],
    proxy: true,
  });
  registerAgents(engine, "alice");
  engine.grantPolicy(
    { secretId: id, principalType: "agent", principalId: "alice", permissions: ["use"] },
    "test-admin",
  );
  return id;
}

/** The fixture key served on the consumer's socket for github.test, its public half derived by a listing. */
async function storeServedKey(fixture = "ed25519_openssh"): Promise<string> {
  const id = await storeSecret(KEY_NAME, readSshFixture(fixture));
  await engine.setInjectionPolicy(KEY_HANDLE, {
    host_allowlist: ["github.test"],
    ssh_agent_socket: true,
  });
  await engine.setConnectionConfig(KEY_HANDLE, {
    ssh: { known_hosts: [fixtureKnownHostsLine("ecdsa384_openssh", "github.test")] },
  });
  registerAgents(engine, CONSUMER);
  engine.grantPolicy(
    { secretId: id, principalType: "agent", principalId: CONSUMER, permissions: ["use"] },
    "test-admin",
  );
  await engine.listAgentSocketIdentities(agentSocketCaller(CONSUMER), null);
  return id;
}

/** The userauth request ssh signs for `keyBlob` in a session bound to github.test's host key. */
function signRequest(keyBlob: Buffer, algorithm: string): AgentSignRequest {
  return {
    keyBlob,
    data: buildUserauthRequest({
      sessionId: SESSION,
      user: "git",
      algorithm,
      publicKeyBlob: keyBlob,
    }),
    flags: 0,
    binding: { hostKeyBlob: HOST_KEY, sessionId: SESSION },
    forwarding: false,
  };
}

function sign(request = signRequest(ED_KEY, "ssh-ed25519")): Promise<Buffer> {
  return engine.signForAgentSocket(agentSocketCaller(CONSUMER), request);
}

/**
 * Every decrypt first awaits `before`, then decrypts through the engine's
 * `onResolved`; with `thenThrow` it throws once that has reported the id.
 */
function atDecrypt(before: () => Promise<void>, thenThrow = false): void {
  const manager = (engine as unknown as { secretManager: SecretManager }).secretManager;
  const decrypt = manager.getSecretValue.bind(manager);
  manager.getSecretValue = async (handle, onResolved) => {
    await before();
    return decrypt(
      handle,
      thenThrow
        ? (id) => {
            onResolved?.(id);
            throw new Error("x");
          }
        : onResolved,
    );
  };
}

/** Every decrypt first revokes the secret `name` and creates another under its name holding `value`. */
function swapAtDecrypt(name: string, value: string, thenThrow = false): void {
  atDecrypt(async () => {
    await engine.revokeSecret(`secret://${name}`);
    await engine.createSecret({
      name,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(value)),
    });
  }, thenThrow);
}

function useRows() {
  return engine
    .queryAudit({ eventType: AuditEventType.SECRET_USE })
    .map((row) => ({ secret_id: row.secret_id, success: row.success, detail: row.detail }));
}

const allZero = (buf: Uint8Array): boolean => buf.every((b) => b === 0);

describe("useSecret — the decrypt bound to the secret the call judged", () => {
  const refused = { handle: HANDLE, context: "http", error: ErrorCode.SECRET_REVOKED };

  it("a use is not handed the value of a secret created under its name", async () => {
    const judged = await storeAllowlisted();
    const retained = retainDecryptedValues(engine);
    swapAtDecrypt("k", OTHER_VALUE);

    await expectVaultError(() => engine.useSecret(HANDLE, HTTP_GET), ErrorCode.SECRET_REVOKED);

    expect(injector).not.toHaveBeenCalled();
    expect(useRows()).toStrictEqual([{ secret_id: judged, success: false, detail: refused }]);
    expect(retained).toHaveLength(1);
    expect(retained.every(allZero)).toBe(true);
  });

  it("a throw of the decrypt after another id was resolved is SECRET_REVOKED", async () => {
    const judged = await storeAllowlisted();
    swapAtDecrypt("k", OTHER_VALUE, true);

    await expectVaultError(() => engine.useSecret(HANDLE, HTTP_GET), ErrorCode.SECRET_REVOKED);

    expect(injector).not.toHaveBeenCalled();
    expect(useRows()).toStrictEqual([{ secret_id: judged, success: false, detail: refused }]);
  });
});

describe("resolveForProxy — the decrypt bound to the secret the call judged", () => {
  const refused = {
    handle: HANDLE,
    context: "proxy",
    method: "GET",
    origin: "https://api.example.com",
    path: "/user",
    error: ErrorCode.SECRET_REVOKED,
    interface: "proxy",
  };

  it("a lease is not handed the value of a secret created under its name", async () => {
    const judged = await storeAllowlisted();
    const retained = retainDecryptedValues(engine);
    swapAtDecrypt("k", OTHER_VALUE);

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, PROXY_CALLER, TARGET),
      ErrorCode.SECRET_REVOKED,
    );

    expect(useRows()).toStrictEqual([{ secret_id: judged, success: false, detail: refused }]);
    expect(retained).toHaveLength(1);
    expect(retained.every(allZero)).toBe(true);
  });

  it("a throw of the decrypt after another id was resolved is SECRET_REVOKED", async () => {
    const judged = await storeAllowlisted();
    swapAtDecrypt("k", OTHER_VALUE, true);

    await expectVaultError(
      () => engine.resolveForProxy(HANDLE, PROXY_CALLER, TARGET),
      ErrorCode.SECRET_REVOKED,
    );

    expect(useRows()).toStrictEqual([{ secret_id: judged, success: false, detail: refused }]);
  });
});

describe("signForAgentSocket — the decrypt bound to the secret and the key the request judged", () => {
  const refused = {
    handle: KEY_HANDLE,
    context: "ssh_agent",
    key_type: "ssh-ed25519",
    error: ErrorCode.SECRET_REVOKED,
    interface: "ssh_agent",
  };

  it("a signature is not made with the key of a secret created under its name", async () => {
    const judged = await storeServedKey();
    const retained = retainDecryptedValues(engine);
    swapAtDecrypt(KEY_NAME, readSshFixture("ecdsa256_openssh"));

    await expectVaultError(() => sign(), ErrorCode.SECRET_REVOKED);

    expect(useRows()).toStrictEqual([{ secret_id: judged, success: false, detail: refused }]);
    expect(retained).toHaveLength(1);
    expect(retained.every(allZero)).toBe(true);
  });

  it("a throw of the decrypt after another id was resolved is SECRET_REVOKED", async () => {
    const judged = await storeServedKey();
    swapAtDecrypt(KEY_NAME, readSshFixture("ecdsa256_openssh"), true);

    await expectVaultError(() => sign(), ErrorCode.SECRET_REVOKED);

    expect(useRows()).toStrictEqual([{ secret_id: judged, success: false, detail: refused }]);
  });

  it("a key rotated under a signature is refused", async () => {
    const judged = await storeServedKey();
    const retained = retainDecryptedValues(engine);
    atDecrypt(() =>
      engine.rotateSecret(
        KEY_HANDLE,
        new Uint8Array(Buffer.from(readSshFixture("ecdsa256_openssh"))),
      ),
    );

    await expectVaultError(() => sign(), ErrorCode.SECRET_NOT_FOUND);

    expect(useRows()).toStrictEqual([
      {
        secret_id: judged,
        success: false,
        detail: {
          context: "ssh_agent",
          key_type: "ssh-ed25519",
          host: "github.test",
          error: ErrorCode.SECRET_NOT_FOUND,
          interface: "ssh_agent",
        },
      },
    ]);
    expect(retained).toHaveLength(1);
    expect(retained.every(allZero)).toBe(true);
  });

  it("a key blob changed during the decrypt does not steer the comparison", async () => {
    const judged = await storeServedKey("ecdsa256_openssh");
    const request = signRequest(Buffer.from(EC_KEY), "ecdsa-sha2-nistp256");
    atDecrypt(async () => {
      await engine.rotateSecret(
        KEY_HANDLE,
        new Uint8Array(Buffer.from(readSshFixture("ecdsa256_pem"))),
      );
      request.keyBlob.set(fixturePublicBlob("ecdsa256_pem"));
    });

    await expectVaultError(() => sign(request), ErrorCode.SECRET_NOT_FOUND);

    expect(useRows()).toStrictEqual([
      {
        secret_id: judged,
        success: false,
        detail: {
          context: "ssh_agent",
          key_type: "ecdsa-sha2-nistp256",
          host: "github.test",
          error: ErrorCode.SECRET_NOT_FOUND,
          interface: "ssh_agent",
        },
      },
    ]);
  });
});
