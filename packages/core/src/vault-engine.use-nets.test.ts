import { randomBytes } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, UseSecretAction } from "@harpoc/shared";
import {
  agentSocketCaller,
  AuditEventType,
  ErrorCode,
  SecretStatus,
  SecretType,
  VaultError,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { registerAgents, registryOf } from "./__fixtures__/engine-seams.js";
import type { AgentRegistry } from "./access/agent-registry.js";
import type { PolicyEngine } from "./access/policy-engine.js";
import {
  buildUserauthRequest,
  fixtureKnownHostsLine,
  fixturePublicBlob,
  readSshFixture,
} from "./injection/__fixtures__/agent-client.js";
import { ENTRY, keyPolicy } from "./injection/__fixtures__/render-entries.js";
import { BLOCK, BOOT } from "./injection/__fixtures__/ssh-public-keys.js";
import { controlledPathDirs, resolveExecutable } from "./injection/allowlist.js";
import type { AgentSignRequest } from "./injection/ssh-agent/agent-connection.js";
import { sshKeyFingerprint } from "./injection/ssh-common-keys.js";
import type { BootstrapOutcome } from "./injection/ssh-injector-bootstrap.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import type { ProxyTarget, SshBootstrapSeam } from "./vault-engine.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

// From the allowlist on, a bootstrap resolves `ssh` on the vault's PATH; a host without one skips.
const SSH_ON_PATH = resolveExecutable("ssh", controlledPathDirs());

const HANDLE = "secret://k";
const KEY_HANDLE = "secret://deploy-ed";
const HTTP = unparsed({ type: "http", method: "GET", url: "https://api.example.com/" });
const TARGET: ProxyTarget = { method: "GET", origin: "https://api.example.com", path: "/x" };
const CONSUMER = "ci-bot";
const ED_KEY = fixturePublicBlob("ed25519_openssh");
const UNKNOWN_KEY = fixturePublicBlob("ed25519_enc");
const HOST_A = fixturePublicBlob("ecdsa384_openssh");
const SESSION = Buffer.alloc(32, 0x5a);
const MARK_AT = 1_700_000_000_000;
const USE_FAILED = "the use failed unexpectedly";
const PROXY_FAILED = "the proxy resolution failed unexpectedly";
const SIGN_FAILED = "the signature failed unexpectedly";
const SPAWN = { exit_code: 0, timed_out: false, network_isolation: false, fs_isolation: false };
const DONE: BootstrapOutcome = {
  kind: "done",
  key: "installed",
  sudoers: "not_asked",
  spawn: SPAWN,
};

let tempDir: string;
let engine: VaultEngine;
let secretId: string;
let keyId: string;

interface EngineInternals {
  secretManager: SecretManager;
  store: SqliteStore;
  agentRegistry: AgentRegistry;
  policyEngine: PolicyEngine;
  sshBootstrap: SshBootstrapSeam;
  loadInjectionPolicy: (...args: unknown[]) => unknown;
  loadConnectionConfig: (...args: unknown[]) => unknown;
  openProxyLease: (...args: unknown[]) => unknown;
  agentSocketKeys: (...args: unknown[]) => Promise<unknown>;
  agentSocketHost: (...args: unknown[]) => unknown;
}

function internals(): EngineInternals {
  return engine as unknown as EngineInternals;
}

function unparsed(value: unknown): UseSecretAction {
  return value as UseSecretAction;
}

function restCaller(id: string): CallerContext {
  return { principal_type: "agent", principal_id: id, interface: "rest" };
}

function proxyCaller(id: string): CallerContext {
  return {
    principal_type: "agent",
    principal_id: id,
    interface: "proxy",
    remote_address: "127.0.0.1",
  };
}

function signRequest(keyBlob: Buffer): AgentSignRequest {
  const data = buildUserauthRequest({
    sessionId: SESSION,
    user: "git",
    algorithm: "ssh-ed25519",
    publicKeyBlob: keyBlob,
  });
  return {
    keyBlob,
    data,
    flags: 0,
    binding: { hostKeyBlob: HOST_A, sessionId: SESSION },
    forwarding: false,
  };
}

function grantUse(id: string, principalId: string): void {
  engine.grantPolicy(
    { secretId: id, principalType: "agent", principalId, permissions: ["use"] },
    "test-admin",
  );
}

function useRows(id?: string) {
  return engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId: id }).reverse();
}

const proxy = (as = "alice"): Promise<unknown> =>
  engine.resolveForProxy(HANDLE, proxyCaller(as), TARGET);
const sign = (as = CONSUMER, keyBlob = ED_KEY): Promise<unknown> =>
  engine.signForAgentSocket(agentSocketCaller(as), signRequest(keyBlob));
const listKeys = async (): Promise<void> => {
  await engine.listAgentSocketIdentities(agentSocketCaller(CONSUMER), null);
};

/** From now on, the `nth` audit insert throws; every other one is written. */
function failAuditInsert(nth: number): void {
  const live = internals().store;
  const insert = live.insertAuditEvent.bind(live);
  let calls = 0;
  vi.spyOn(live, "insertAuditEvent").mockImplementation(
    (...args: Parameters<SqliteStore["insertAuditEvent"]>) => {
      calls += 1;
      if (calls === nth) throw new Error("boom");
      return insert(...args);
    },
  );
}

function failDecrypt(): void {
  vi.spyOn(internals().secretManager, "getSecretValue").mockRejectedValue(
    VaultError.vaultCorrupted("the value does not decrypt"),
  );
}

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-use-nets-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  await engine.createSecret({
    name: "k",
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(randomBytes(18).toString("base64url"))),
  });
  secretId = await engine.resolveSecretId(HANDLE);
  await engine.setInjectionPolicy(HANDLE, {
    url_allowlist: ["https://api.example.com/*"],
    proxy: true,
  });
  await engine.createSecret({
    name: "deploy-ed",
    type: SecretType.API_KEY,
    value: new Uint8Array(Buffer.from(readSshFixture("ed25519_openssh"))),
  });
  keyId = await engine.resolveSecretId(KEY_HANDLE);
  await engine.setInjectionPolicy(KEY_HANDLE, {
    host_allowlist: ["github.test"],
    ssh_agent_socket: true,
  });
  await engine.setConnectionConfig(KEY_HANDLE, {
    ssh: { known_hosts: [fixtureKnownHostsLine("ecdsa384_openssh", "github.test")] },
  });
  registerAgents(engine, "alice", "bob", CONSUMER, "other-bot");
  grantUse(secretId, "alice");
  grantUse(keyId, CONSUMER);
});

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("the nets of resolveForProxy and signForAgentSocket", () => {
  const PROXY_ROW = {
    context: "proxy",
    method: "GET",
    origin: "https://api.example.com",
    path: "/x",
    error: ErrorCode.INTERNAL_ERROR,
    interface: "proxy",
  };
  const SIGNED_ROW = {
    context: "ssh_agent",
    key_type: "ssh-ed25519",
    error: ErrorCode.INTERNAL_ERROR,
    interface: "ssh_agent",
  };
  const UNRESOLVED_ROW = {
    context: "ssh_agent",
    key_fingerprint: sshKeyFingerprint(ED_KEY),
    error: ErrorCode.INTERNAL_ERROR,
    interface: "ssh_agent",
  };

  const throwBoom = (): never => {
    throw new Error("boom");
  };

  it.each([
    {
      at: "resolveForProxy: the policy's read",
      inject: () => {
        vi.spyOn(internals(), "loadInjectionPolicy").mockImplementation(throwBoom);
      },
      call: () => proxy(),
      message: PROXY_FAILED,
      on: "secret",
      detail: PROXY_ROW,
    },
    {
      at: "resolveForProxy: the mark's read",
      inject: () => {
        vi.spyOn(internals().store, "readBootstrapMark").mockImplementation(throwBoom);
      },
      call: () => proxy(),
      message: PROXY_FAILED,
      on: "secret",
      detail: PROXY_ROW,
    },
    {
      at: "resolveForProxy: the CA pin's read",
      inject: () => {
        vi.spyOn(internals(), "loadConnectionConfig").mockImplementation(throwBoom);
      },
      call: () => proxy(),
      message: PROXY_FAILED,
      on: "secret",
      detail: PROXY_ROW,
    },
    {
      at: "resolveForProxy: the lease's opening",
      inject: () => {
        vi.spyOn(internals(), "openProxyLease").mockImplementation(throwBoom);
      },
      call: () => proxy(),
      message: PROXY_FAILED,
      on: "secret",
      detail: PROXY_ROW,
    },
    {
      at: "resolveForProxy: a refusal row's insert",
      inject: async () => {
        await engine.setInjectionPolicy(HANDLE, { url_allowlist: ["https://api.example.com/*"] });
        failAuditInsert(1);
      },
      call: () => proxy(),
      message: PROXY_FAILED,
      on: "secret",
      detail: PROXY_ROW,
    },
    {
      at: "signForAgentSocket: the registry's lookup",
      inject: () => {
        vi.spyOn(internals().agentRegistry, "findByName").mockImplementation(throwBoom);
      },
      call: () => sign(),
      message: SIGN_FAILED,
      on: null,
      detail: UNRESOLVED_ROW,
    },
    {
      at: "signForAgentSocket: the servable keys",
      inject: () => {
        vi.spyOn(internals(), "agentSocketKeys").mockRejectedValue(new Error("boom"));
      },
      call: () => sign(),
      message: SIGN_FAILED,
      on: null,
      detail: UNRESOLVED_ROW,
    },
    {
      at: "signForAgentSocket: the policy's read",
      inject: () => {
        const load = internals().loadInjectionPolicy.bind(engine);
        vi.spyOn(internals(), "loadInjectionPolicy")
          .mockImplementationOnce(load)
          .mockImplementation(throwBoom);
      },
      call: () => sign(),
      message: SIGN_FAILED,
      on: "key",
      detail: SIGNED_ROW,
    },
    {
      at: "signForAgentSocket: the mark's read",
      inject: () => {
        const live = internals().store;
        const read = live.readBootstrapMark.bind(live);
        vi.spyOn(live, "readBootstrapMark")
          .mockImplementationOnce(read)
          .mockImplementation(throwBoom);
      },
      call: () => sign(),
      message: SIGN_FAILED,
      on: "key",
      detail: SIGNED_ROW,
    },
    {
      at: "signForAgentSocket: the pinned host's lookup",
      inject: () => {
        vi.spyOn(internals(), "agentSocketHost").mockImplementation(throwBoom);
      },
      call: () => sign(),
      message: SIGN_FAILED,
      on: "key",
      detail: SIGNED_ROW,
    },
  ])(
    "$at: a raw throw leaves as INTERNAL_ERROR with one failed row",
    async ({ inject, call, message, on, detail }) => {
      await inject();

      const err = await expectVaultError(call, ErrorCode.INTERNAL_ERROR);

      expect(err.message).toBe(message);
      expect(err.message.includes("boom")).toBe(false);
      const id = on === "secret" ? secretId : on === "key" ? keyId : null;
      expect(useRows().map((row) => [row.secret_id, row.success, row.detail])).toStrictEqual([
        [id, false, detail],
      ]);
    },
  );

  it.each([
    {
      name: "resolveForProxy",
      inject: () => {
        vi.spyOn(internals(), "loadInjectionPolicy").mockImplementation(throwBoom);
      },
      call: () => proxy(),
    },
    {
      name: "signForAgentSocket",
      inject: () => {
        vi.spyOn(internals(), "agentSocketHost").mockImplementation(throwBoom);
      },
      call: () => sign(),
    },
  ])(
    "$name: a row the net cannot write leaves as the audit failure, never raw",
    async ({ inject, call }) => {
      inject();
      vi.spyOn(internals().store, "insertAuditEvent").mockImplementation(() => {
        throw new Error("audit unavailable");
      });

      const err = await expectVaultError(call, ErrorCode.INTERNAL_ERROR);

      expect(err.message).toBe("the audit write failed unexpectedly");
      vi.restoreAllMocks();
      expect(useRows()).toHaveLength(0);
    },
  );

  it("a VaultError passes the proxy's net untouched, with no second row", async () => {
    const err = await expectVaultError(
      () => engine.resolveForProxy("secret://nope", proxyCaller("alice"), TARGET),
      ErrorCode.SECRET_NOT_FOUND,
    );

    expect(err.message).toBe(VaultError.secretNotFound("secret://nope").message);
    expect(useRows().map((row) => [row.secret_id, row.detail?.error])).toStrictEqual([
      [null, ErrorCode.SECRET_NOT_FOUND],
    ]);
  });

  it("a VaultError passes the agent socket's net untouched, with no second row", async () => {
    const err = await expectVaultError(
      () => sign(CONSUMER, UNKNOWN_KEY),
      ErrorCode.SECRET_NOT_FOUND,
    );

    expect(err.message).toBe(VaultError.secretNotFound().message);
    expect(useRows().map((row) => [row.secret_id, row.detail?.error])).toStrictEqual([
      [null, ErrorCode.SECRET_NOT_FOUND],
    ]);
  });

  const failUsable = (): void => {
    vi.spyOn(internals().secretManager, "assertUsable").mockImplementation(throwBoom);
  };
  const failDecryptRaw = (): void => {
    vi.spyOn(internals().secretManager, "getSecretValue").mockRejectedValue(new Error("boom"));
  };

  it.each([
    {
      block: "resolveForProxy: the status block",
      arrange: failUsable,
      call: () => proxy(),
      on: "secret",
      handle: HANDLE,
    },
    {
      block: "resolveForProxy: the decrypt block",
      arrange: failDecryptRaw,
      call: () => proxy(),
      on: "secret",
      handle: HANDLE,
    },
    {
      block: "signForAgentSocket: the status block",
      arrange: async () => {
        await listKeys();
        failUsable();
      },
      call: () => sign(),
      on: "key",
      handle: KEY_HANDLE,
    },
    {
      block: "signForAgentSocket: the decrypt block",
      arrange: async () => {
        await listKeys();
        failDecryptRaw();
      },
      call: () => sign(),
      on: "key",
      handle: KEY_HANDLE,
    },
  ])(
    "$block: a raw throw leaves as INTERNAL_ERROR with the block's one row",
    async ({ arrange, call, on, handle }) => {
      await arrange();

      const err = await expectVaultError(call, ErrorCode.INTERNAL_ERROR);

      const id = on === "key" ? keyId : secretId;
      expect(
        useRows().map((row) => [row.secret_id, row.detail?.handle, row.detail?.error]),
      ).toStrictEqual([[id, handle, ErrorCode.INTERNAL_ERROR]]);
      expect(err.message).toBe("the injection context failed unexpectedly");
      expect(err.message.includes("boom")).toBe(false);
    },
  );

  it("signForAgentSocket: a raw throw of the request's reads leaves as INTERNAL_ERROR with one row", async () => {
    const request = Object.defineProperty({ ...signRequest(ED_KEY) }, "keyBlob", {
      get: throwBoom,
    }) as AgentSignRequest;

    const err = await expectVaultError(
      () => engine.signForAgentSocket(agentSocketCaller(CONSUMER), request),
      ErrorCode.INTERNAL_ERROR,
    );

    expect(err.message).toBe(SIGN_FAILED);
    expect(err.message.includes("boom")).toBe(false);
    expect(useRows().map((row) => [row.secret_id, row.success, row.detail])).toStrictEqual([
      [
        null,
        false,
        { context: "ssh_agent", error: ErrorCode.INTERNAL_ERROR, interface: "ssh_agent" },
      ],
    ]);
  });
});

describe("one refusal, one row: a terminate that fails after the refusal's row", () => {
  const ALICE = restCaller("alice");

  it.each([
    {
      site: "the use path's grant",
      arrange: () => undefined,
      call: () => engine.useSecret(HANDLE, HTTP, restCaller("bob")),
      on: "secret",
      reason: "use_denied",
      errors: [ErrorCode.ACCESS_DENIED],
    },
    {
      site: "the use path's status",
      arrange: () => engine.revokeSecret(HANDLE),
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      reason: "secret_unusable",
      errors: [ErrorCode.SECRET_REVOKED],
    },
    {
      site: "the use path's render entry",
      arrange: () => engine.setInjectionPolicy(HANDLE, keyPolicy([ENTRY])),
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      reason: "render_enabled",
      errors: [ErrorCode.RENDER_ONLY_KEY],
    },
    {
      site: "the use path's bootstrap block",
      arrange: () => engine.setInjectionPolicy(HANDLE, { ssh_bootstrap: BLOCK }),
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      reason: "ssh_bootstrap_enabled",
      errors: [ErrorCode.SSH_BOOTSTRAP_NOT_ALLOWED],
    },
    {
      site: "the use path's mark",
      arrange: () => internals().store.claimBootstrapMark(secretId, "claim-other", MARK_AT),
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      reason: "secret_revoked",
      errors: [ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED],
    },
    {
      site: "the use path's decrypt",
      arrange: failDecrypt,
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      reason: "secret_unusable",
      errors: [ErrorCode.VAULT_CORRUPTED],
    },
    {
      site: "the proxy's grant",
      arrange: () => undefined,
      call: () => proxy("bob"),
      on: "secret",
      reason: "use_denied",
      errors: [ErrorCode.ACCESS_DENIED],
    },
    {
      site: "the proxy's status",
      arrange: () => engine.revokeSecret(HANDLE),
      call: () => proxy(),
      on: "secret",
      reason: "secret_unusable",
      errors: [ErrorCode.SECRET_REVOKED],
    },
    {
      site: "the proxy's decrypt",
      arrange: failDecrypt,
      call: () => proxy(),
      on: "secret",
      reason: "secret_unusable",
      errors: [ErrorCode.VAULT_CORRUPTED],
    },
    {
      site: "the agent socket's grant",
      arrange: listKeys,
      call: () => sign("other-bot"),
      on: "key",
      reason: "use_denied",
      errors: [ErrorCode.ACCESS_DENIED],
    },
    {
      site: "the agent socket's status",
      arrange: async () => {
        await listKeys();
        await engine.revokeSecret(KEY_HANDLE);
      },
      call: () => sign(),
      on: "key",
      reason: "secret_unusable",
      errors: [ErrorCode.SECRET_REVOKED],
    },
  ])(
    "$site: INTERNAL_ERROR, and the refusal's row is the one row",
    async ({ arrange, call, on, reason, errors }) => {
      await arrange();
      const terminate = vi
        .spyOn(registryOf(engine), "terminate")
        .mockRejectedValue(new Error("boom"));

      const err = await expectVaultError(call, ErrorCode.INTERNAL_ERROR);

      expect(err.message).toBe(USE_FAILED);
      const id = on === "key" ? keyId : secretId;
      expect(terminate).toHaveBeenCalledWith(id, reason, expect.anything());
      expect(useRows(id).map((row) => row.detail?.error)).toStrictEqual(errors);
    },
  );

  it("a terminate that fails with a VaultError passes", async () => {
    await engine.revokeSecret(HANDLE);
    const thrown = VaultError.internalError("audit");
    vi.spyOn(registryOf(engine), "terminate").mockRejectedValue(thrown);

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, HTTP, ALICE),
      ErrorCode.INTERNAL_ERROR,
    );

    expect(err).toBe(thrown);
    expect(useRows(secretId).map((row) => row.detail?.error)).toStrictEqual([
      ErrorCode.SECRET_REVOKED,
    ]);
  });

  function failGrantCheck(): void {
    vi.spyOn(internals().policyEngine, "grantedPermissions").mockImplementation(() => {
      throw new Error("boom");
    });
  }

  it.each([
    {
      site: "the use path's grant",
      arrange: failGrantCheck,
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      message: USE_FAILED,
    },
    {
      site: "the use path's render entry",
      arrange: async () => {
        await engine.setInjectionPolicy(HANDLE, keyPolicy([ENTRY]));
        failAuditInsert(1);
      },
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      message: USE_FAILED,
    },
    {
      site: "the use path's bootstrap block",
      arrange: async () => {
        await engine.setInjectionPolicy(HANDLE, { ssh_bootstrap: BLOCK });
        failAuditInsert(1);
      },
      call: () => engine.useSecret(HANDLE, HTTP, ALICE),
      on: "secret",
      message: USE_FAILED,
    },
    {
      site: "the proxy's grant",
      arrange: failGrantCheck,
      call: () => proxy(),
      on: "secret",
      message: PROXY_FAILED,
    },
    {
      site: "the agent socket's grant",
      arrange: failGrantCheck,
      call: () => sign(),
      on: "key",
      message: SIGN_FAILED,
    },
  ])(
    "$site: a raw throw before the refusal's row, then a raw terminate, leaves the net's one row",
    async ({ arrange, call, on, message }) => {
      await arrange();
      vi.spyOn(registryOf(engine), "terminate").mockRejectedValue(new Error("boom"));

      const err = await expectVaultError(call, ErrorCode.INTERNAL_ERROR);

      expect(err.message).toBe(message);
      const id = on === "key" ? keyId : secretId;
      expect(useRows(id).map((row) => row.detail?.error)).toStrictEqual([ErrorCode.INTERNAL_ERROR]);
    },
  );
});

describe.skipIf(SSH_ON_PATH === null)(
  "one refusal, one row: a terminate that fails after a bootstrap's row",
  () => {
    function installSeam(outcome: BootstrapOutcome): void {
      internals().sshBootstrap = {
        refuseVaultHost: () => undefined,
        refuseOldClient: () => Promise.resolve(),
        run: () => Promise.resolve(outcome),
      };
    }

    function afterDecrypt(then: () => void): void {
      const manager = internals().secretManager;
      const decrypt = manager.getSecretValue.bind(manager);
      vi.spyOn(manager, "getSecretValue").mockImplementation(
        async (...args: Parameters<SecretManager["getSecretValue"]>) => {
          const value = await decrypt(...args);
          then();
          return value;
        },
      );
    }

    beforeEach(async () => {
      await engine.setInjectionPolicy(HANDLE, {
        command_allowlist: ["ssh"],
        ssh_bootstrap: BLOCK,
      });
    });

    it.each([
      {
        site: "the claim that meets a mark nobody holds",
        arrange: () => {
          installSeam(DONE);
          afterDecrypt(() => {
            internals().store.claimBootstrapMark(secretId, "claim-other", MARK_AT);
          });
        },
        reason: "secret_revoked",
        errors: [ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED],
      },
      {
        site: "the outcome that ends the secret",
        arrange: () => {
          installSeam({ kind: "unconfirmed", spawn: SPAWN } as BootstrapOutcome);
        },
        reason: "secret_revoked",
        errors: [undefined, ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED],
      },
      {
        site: "the claim of a secret revoked under it",
        arrange: () => {
          installSeam(DONE);
          afterDecrypt(() => {
            internals().store.updateSecret(secretId, { status: SecretStatus.REVOKED });
          });
        },
        reason: "secret_unusable",
        errors: [ErrorCode.SECRET_REVOKED],
      },
    ])(
      "$site: INTERNAL_ERROR, and the bootstrap's rows are all",
      async ({ arrange, reason, errors }) => {
        arrange();
        const terminate = vi
          .spyOn(registryOf(engine), "terminate")
          .mockRejectedValue(new Error("boom"));

        const err = await expectVaultError(
          () => engine.useSecret(HANDLE, BOOT, restCaller("alice")),
          ErrorCode.INTERNAL_ERROR,
        );

        expect(err.message).toBe(USE_FAILED);
        expect(terminate).toHaveBeenCalledWith(secretId, reason, expect.anything());
        expect(useRows(secretId).map((row) => row.detail?.error)).toStrictEqual(errors);
      },
    );
  },
);
