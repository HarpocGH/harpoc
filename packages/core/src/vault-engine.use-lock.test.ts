import { randomBytes } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { CallerContext, OAuthProviderConfig, UseSecretAction } from "@harpoc/shared";
import {
  agentSocketCaller,
  AuditEventType,
  ErrorCode,
  SecretStatus,
  SecretType,
  VaultError,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import {
  nonReadAuditCount,
  registerAgents,
  registryOf,
  retainDecryptedValues,
  seedLiveStdioEntry,
} from "./__fixtures__/engine-seams.js";
import { readRow, useOAuthEngine } from "./__fixtures__/oauth-engine.js";
import type { AuditAttribution } from "./audit/attribution.js";
import { withAttribution } from "./audit/attribution.js";
import type { AuditLogger } from "./audit/audit-logger.js";
import {
  buildUserauthRequest,
  fixtureKnownHostsLine,
  fixturePublicBlob,
  readSshFixture,
} from "./injection/__fixtures__/agent-client.js";
import { BLOCK, BOOT } from "./injection/__fixtures__/ssh-public-keys.js";
import { controlledPathDirs, resolveExecutable } from "./injection/allowlist.js";
import { StdioChildTransport } from "./injection/mcp-stdio-transport.js";
import { validateHostPort, validateUrl } from "./injection/url-validator.js";
import type { SecretManager } from "./secrets/secret-manager.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import type { ProxyTarget, SshBootstrapSeam } from "./vault-engine.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

vi.mock("./injection/url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(actual.validateUrl),
    validateHostPort: vi.fn(actual.validateHostPort),
  };
});

// From the allowlist on, a bootstrap resolves `ssh` on the vault's PATH; a host without one skips.
const SSH_ON_PATH = resolveExecutable("ssh", controlledPathDirs());

const HANDLE = "secret://k";
const PAIR = "secret://pair";
const PLAIN = "secret://plain";
const UNKNOWN = "secret://nope";
const HTTP = { type: "http", method: "GET", url: "https://api.example.com/" } as UseSecretAction;
const TARGET: ProxyTarget = { method: "GET", origin: "https://api.example.com", path: "/x" };
const ALICE: CallerContext = { principal_type: "agent", principal_id: "alice", interface: "rest" };
const PROXY_CALLER: CallerContext = {
  principal_type: "agent",
  principal_id: "alice",
  interface: "proxy",
  remote_address: "127.0.0.1",
};
const CONSUMER = "ci-bot";
const ED_KEY = fixturePublicBlob("ed25519_openssh");
const HOST_A = fixturePublicBlob("ecdsa384_openssh");
const SESSION = Buffer.alloc(32, 0x5a);
const ACCESS_TOKEN = "S3CRET-TOKEN-access";
const REFRESH_TOKEN = "S3CRET-TOKEN-refresh";
const CLIENT_SECRET = "S3CRET-TOKEN-operator";
const RENEWED = "S3CRET-TOKEN-renewed";
const MCP = "secret://mcp";
/** Under MCP_INIT_TIMEOUT_MS: a child the wipe leaves in its handshake ends only at that bound. */
const GONE_TIMEOUT_MS = 10_000;

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

interface EngineInternals {
  secretManager: SecretManager;
  store: SqliteStore;
  auditLogger: AuditLogger;
  kek: Uint8Array | null;
  auditKey: Uint8Array | null;
  openRenders: Set<() => void>;
  sshBootstrap: SshBootstrapSeam;
  httpInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
  sealExpired(): void;
}

type Wipe = () => Promise<void>;

function allZero(array: Uint8Array): boolean {
  return array.every((byte) => byte === 0);
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw err;
  }
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

function quiet<T>(promise: Promise<T>): Promise<T> {
  promise.catch(() => undefined);
  return promise;
}

/** `name` on `target` wrapped: the awaited call goes through, then `wipe` lands before its caller resumes. */
function wipeDuring(target: object, name: string, wipe: Wipe): void {
  const methods = target as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const original = (methods[name] as (...args: unknown[]) => Promise<unknown>).bind(target);
  vi.spyOn(methods, name).mockImplementation(async (...args: unknown[]) => {
    const answer = await original(...args);
    await wipe();
    return answer;
  });
}

describe("a call acts under the state it began with", () => {
  let tempDir: string;
  let engine: VaultEngine;
  let secretId: string;

  const at = (): EngineInternals => engine as unknown as EngineInternals;

  const WIPES = [
    { wipe: "lock()", run: (): Promise<void> => engine.lock(), lockRows: 1 },
    {
      wipe: "sealExpired()",
      run: (): Promise<void> => {
        at().sealExpired();
        return Promise.resolve();
      },
      lockRows: 0,
    },
  ];

  const use = (handle = HANDLE): Promise<unknown> => engine.useSecret(handle, HTTP, ALICE);
  const proxy = (handle = HANDLE): Promise<unknown> =>
    engine.resolveForProxy(handle, PROXY_CALLER, TARGET);
  const sign = (): Promise<unknown> =>
    engine.signForAgentSocket(agentSocketCaller(CONSUMER), {
      keyBlob: ED_KEY,
      data: buildUserauthRequest({
        sessionId: SESSION,
        user: "git",
        algorithm: "ssh-ed25519",
        publicKeyBlob: ED_KEY,
      }),
      flags: 0,
      binding: { hostKeyBlob: HOST_A, sessionId: SESSION },
      forwarding: false,
    });
  const listKeys = async (): Promise<void> => {
    await engine.listAgentSocketIdentities(agentSocketCaller(CONSUMER), null);
  };

  async function addSecret(name: string, value: string): Promise<string> {
    await engine.createSecret({
      name,
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from(value)),
    });
    return engine.resolveSecretId(`secret://${name}`);
  }

  function grantUse(id: string, principalId: string): void {
    engine.grantPolicy(
      { secretId: id, principalType: "agent", principalId, permissions: ["use"] },
      "test-admin",
    );
  }

  beforeEach(async () => {
    tempDir = join(
      tmpdir(),
      `harpoc-use-lock-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(tempDir, { recursive: true });
    engine = new VaultEngine({
      dbPath: join(tempDir, "test.vault.db"),
      sessionPath: join(tempDir, "session.json"),
    });
    await engine.initVault("password");
    secretId = await addSecret("k", randomBytes(18).toString("base64url"));
    await engine.setInjectionPolicy(HANDLE, {
      url_allowlist: ["https://api.example.com/*"],
      proxy: true,
    });
    const keyId = await addSecret("deploy-ed", readSshFixture("ed25519_openssh"));
    await engine.setInjectionPolicy("secret://deploy-ed", {
      host_allowlist: ["github.test"],
      ssh_agent_socket: true,
    });
    await engine.setConnectionConfig("secret://deploy-ed", {
      ssh: { known_hosts: [fixtureKnownHostsLine("ecdsa384_openssh", "github.test")] },
    });
    registerAgents(engine, "alice", CONSUMER);
    grantUse(secretId, "alice");
    grantUse(keyId, CONSUMER);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    try {
      await engine.unlock("password");
      expect(engine.verifyAuditChain().valid).toBe(true);
    } finally {
      await engine.destroy();
      rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  const WAITS = [
    {
      path: "a use",
      wait: "the handle's resolution",
      arrange: async (wipe: Wipe) => wipeDuring(at().secretManager, "resolveHandle", wipe),
      call: () => use(),
      rows: 0,
    },
    {
      path: "a use",
      wait: "concealHandleError",
      arrange: async (wipe: Wipe) => wipeDuring(engine, "concealHandleError", wipe),
      call: () => use(UNKNOWN),
      rows: 1,
    },
    {
      path: "a use",
      wait: "refuseOnBootstrapMark",
      arrange: async (wipe: Wipe) => wipeDuring(engine, "refuseOnBootstrapMark", wipe),
      call: () => use(),
      rows: 0,
    },
    {
      path: "a proxied resolve",
      wait: "the handle's resolution",
      arrange: async (wipe: Wipe) => wipeDuring(at().secretManager, "resolveHandle", wipe),
      call: () => proxy(),
      rows: 0,
    },
    {
      path: "a proxied resolve",
      wait: "concealHandleError",
      arrange: async (wipe: Wipe) => wipeDuring(engine, "concealHandleError", wipe),
      call: () => proxy(UNKNOWN),
      rows: 1,
    },
    {
      path: "a proxied resolve",
      wait: "refuseOnBootstrapMark",
      arrange: async (wipe: Wipe) => wipeDuring(engine, "refuseOnBootstrapMark", wipe),
      call: () => proxy(),
      rows: 0,
    },
    {
      path: "a signature",
      wait: "its servable keys",
      arrange: async (wipe: Wipe) => {
        await listKeys();
        wipeDuring(engine, "agentSocketKeys", wipe);
      },
      call: sign,
      rows: 0,
    },
    {
      path: "a signature",
      wait: "refuseOnBootstrapMark",
      arrange: async (wipe: Wipe) => {
        await listKeys();
        wipeDuring(engine, "refuseOnBootstrapMark", wipe);
      },
      call: sign,
      rows: 0,
    },
  ];

  describe.each(WIPES)("a wipe by $wipe", ({ run, lockRows }) => {
    it.each(WAITS)(
      "$path: a wipe during $wait answers VAULT_LOCKED with no row and reads no value",
      async ({ arrange, call, rows }) => {
        await arrange(run);
        const count = nonReadAuditCount(engine);
        const decrypt = vi.spyOn(at().secretManager, "getSecretValue");

        await expectVaultError(call, ErrorCode.VAULT_LOCKED);

        expect(decrypt).not.toHaveBeenCalled();
        await engine.unlock("password");
        expect(nonReadAuditCount(engine)).toBe(count + rows + lockRows + 1);
      },
    );

    it("a lazy expiry after a wipe writes no status without its row", async () => {
      const plainId = await addSecret("plain", randomBytes(18).toString("base64url"));
      grantUse(plainId, "alice");
      at().store.updateSecret(plainId, { expires_at: Date.now() - 1000 });
      wipeDuring(at().secretManager, "resolveHandle", run);

      await expectVaultError(() => use(PLAIN), ErrorCode.VAULT_LOCKED);

      await engine.unlock("password");
      expect(at().store.getSecret(plainId)?.status).toBe(SecretStatus.ACTIVE);
      expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE })).toStrictEqual([]);
    });

    it("no row is written under a zeroed key", async () => {
      const logger = at().auditLogger;
      at().httpInjector = {
        executeWithSecret: async () => {
          await run();
          logger.log({
            eventType: AuditEventType.SECRET_USE,
            secretId,
            detail: { context: "http", status: 200 },
          });
          return { type: "http", status: 200 };
        },
      };

      await expectVaultError(() => use(), ErrorCode.VAULT_LOCKED);

      await engine.unlock("password");
      const unreadable = engine.queryAudit().filter((row) => row.detail_unreadable === true);
      expect(unreadable.map((row) => [row.id, row.event_type])).toStrictEqual([]);
    });

    it("the wipe leaves no chain key", async () => {
      const logger = at().auditLogger;

      await run();

      expect(allZero((logger as unknown as { chainKey: Uint8Array }).chainKey)).toBe(true);
      expect(logger.sealed).toBe(true);
    });

    it("a render seal that throws does not keep the keys", async () => {
      const kek = at().kek as Uint8Array;
      const auditKey = at().auditKey as Uint8Array;
      const seal = (): void => {
        throw new Error("the seal failed");
      };
      at().openRenders.add(seal);

      try {
        await run();
      } finally {
        at().openRenders.delete(seal);
      }

      expect(allZero(kek)).toBe(true);
      expect(allZero(auditKey)).toBe(true);
    });
  });

  describe.skipIf(SSH_ON_PATH === null)("a bootstrap", () => {
    let oldClient: Mock<SshBootstrapSeam["refuseOldClient"]>;

    beforeEach(async () => {
      await engine.setInjectionPolicy(HANDLE, { command_allowlist: ["ssh"], ssh_bootstrap: BLOCK });
      oldClient = vi.fn<SshBootstrapSeam["refuseOldClient"]>(() => Promise.resolve());
      at().sshBootstrap = {
        refuseVaultHost: () => undefined,
        refuseOldClient: oldClient,
        run: () => Promise.reject(new Error("the bootstrap must not run")),
      };
    });

    describe.each(WIPES)("a wipe by $wipe", ({ run, lockRows }) => {
      it.each([
        { wait: "its mark", wrap: "refuseOnBootstrapMark", versionReads: 0 },
        { wait: "its judgement", wrap: "judgeBootstrapAction", versionReads: 1 },
      ])(
        "a wipe during $wait answers VAULT_LOCKED with no row and reads no value",
        async ({ wrap, versionReads }) => {
          wipeDuring(engine, wrap, run);
          const count = nonReadAuditCount(engine);
          const decrypt = vi.spyOn(at().secretManager, "getSecretValue");

          await expectVaultError(
            () => engine.useSecret(HANDLE, BOOT, ALICE),
            ErrorCode.VAULT_LOCKED,
          );

          expect(decrypt).not.toHaveBeenCalled();
          expect(oldClient).toHaveBeenCalledTimes(versionReads);
          await engine.unlock("password");
          expect(nonReadAuditCount(engine)).toBe(count + lockRows + 1);
        },
      );
    });
  });

  describe.each([
    {
      how: "locked and unlocked again",
      reunlock: async (): Promise<void> => {
        await engine.lock();
        await engine.unlock("password");
      },
    },
    { how: "unlocked again over the live engine", reunlock: () => engine.unlock("password") },
  ])("$how under a call", ({ reunlock }) => {
    it.each([
      {
        path: "a use",
        arrange: async (wipe: Wipe) => wipeDuring(at().secretManager, "resolveHandle", wipe),
        call: () => use(),
      },
      {
        path: "a proxied resolve",
        arrange: async (wipe: Wipe) => wipeDuring(at().secretManager, "resolveHandle", wipe),
        call: () => proxy(),
      },
      {
        path: "a signature",
        arrange: async (wipe: Wipe) => {
          await listKeys();
          wipeDuring(engine, "agentSocketKeys", wipe);
        },
        call: sign,
      },
      {
        path: "a proxied resolve's decrypt",
        arrange: async (wipe: Wipe) => wipeDuring(at().secretManager, "getSecretValue", wipe),
        call: () => proxy(),
      },
      {
        path: "a signature's decrypt",
        arrange: async (wipe: Wipe) => {
          await listKeys();
          wipeDuring(at().secretManager, "getSecretValue", wipe);
        },
        call: sign,
      },
      {
        path: "a signature's decrypt of a key not derived yet",
        arrange: async (wipe: Wipe) => wipeDuring(at().secretManager, "findByHandle", wipe),
        call: sign,
      },
    ])("$path that outlives it writes nothing into the new session", async ({ arrange, call }) => {
      let count = -1;
      await arrange(async () => {
        await reunlock();
        count = nonReadAuditCount(engine);
      });

      await expectVaultError(call, ErrorCode.VAULT_LOCKED);

      expect(nonReadAuditCount(engine)).toBe(count);
      expect(engine.verifyAuditChain().valid).toBe(true);
    });
  });

  it("a lazy expiry through a manager taken before the lock rolls its status back", async () => {
    const plainId = await addSecret("plain", randomBytes(18).toString("base64url"));
    at().store.updateSecret(plainId, { expires_at: Date.now() - 1000 });
    const manager = at().secretManager;
    const secret = await manager.resolveHandle(PLAIN);
    await engine.lock();

    await expectVaultError(() => manager.assertUsable(secret, PLAIN), ErrorCode.VAULT_LOCKED);

    await engine.unlock("password");
    expect(at().store.getSecret(plainId)?.status).toBe(SecretStatus.ACTIVE);
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE })).toStrictEqual([]);
  });

  describe("a use open at a wipe", () => {
    const sealExpired = (): void => at().sealExpired();
    const lockedRow = (callerInterface: string): unknown => ({
      success: false,
      detail: {
        handle: HANDLE,
        context: "http",
        error: ErrorCode.VAULT_LOCKED,
        interface: callerInterface,
      },
    });
    const STUB_ROW = { success: true, detail: { context: "http", status: 200, interface: "rest" } };

    const CONTEXTS: { context: string; action: UseSecretAction }[] = [
      { context: "http", action: HTTP },
      { context: "process", action: { type: "process", command: "x", env_var: "T" } },
      {
        context: "database",
        action: {
          type: "database",
          engine: "postgresql",
          host: "db.example.com",
          database: "app",
          query: "SELECT 1",
        },
      },
      {
        context: "ssh",
        action: { type: "ssh", host: "deploy.example.com", user: "deploy", command: "whoami" },
      },
      {
        context: "git",
        action: { type: "git", operation: "clone", repository: "https://git.example.com/o/r.git" },
      },
      {
        context: "smtp",
        action: {
          type: "smtp",
          host: "smtp.example.com",
          security: "tls",
          from: "ops@example.com",
          to: ["dev@example.com"],
          subject: "build finished",
          text: "green",
        },
      },
      {
        context: "imap",
        action: {
          type: "imap",
          host: "imap.example.com",
          port: 993,
          mailbox: "INBOX",
          operation: { kind: "search", unseen: true },
        },
      },
      {
        context: "websocket",
        action: {
          type: "websocket",
          url: "wss://stream.example.com/feed",
          injection: { type: "bearer" },
          message: "ping",
        },
      },
      {
        context: "sftp",
        action: {
          type: "sftp",
          host: "deploy.example.com",
          user: "deploy",
          operation: "list",
          remote_path: "/srv",
        },
      },
      {
        context: "docker_registry",
        action: {
          type: "docker_registry",
          operation: "pull",
          image: "registry.example.com/app:1.0",
          timeout_ms: 300_000,
        },
      },
    ];

    /** Where each injector that writes its own row takes the attribution among its arguments. */
    const ATTRIBUTION_AT: Record<string, number> = {
      http: 5,
      process: 4,
      database: 5,
      ssh: 5,
      git: 5,
    };

    /** The seams that write no row of their own, each stood in for: it awaits `answer`, then answers; the engine writes the row. */
    const ENGINE_AUDITED: Record<string, (answer: () => Promise<unknown>) => object> = {
      smtp: (answer) => ({
        smtpInjector: {
          run: async () => {
            await answer();
            return { result: { type: "smtp", accepted: 1, message_id: "<m@x>" }, auditDetails: {} };
          },
        },
      }),
      imap: (answer) => ({
        imapInjector: {
          run: async () => {
            await answer();
            return {
              result: { type: "imap", operation: "search", uids: [] },
              auditDetails: {},
              sanitized: false,
            };
          },
        },
      }),
      websocket: (answer) => ({
        websocketExecutor: async () => {
          await answer();
          return {
            result: { type: "websocket", messages: [], close_code: 1000 },
            sanitized: false,
          };
        },
      }),
      sftp: (answer) => ({
        sftpExecutor: async () => {
          await answer();
          return {
            result: { type: "sftp", exit_code: 0, stdout: "", stderr: "" },
            sanitized: false,
          };
        },
      }),
      docker_registry: (answer) => ({
        dockerExecutor: async () => {
          await answer();
          return {
            result: {
              type: "docker_registry",
              operation: "pull",
              exit_code: 0,
              stdout: "",
              stderr: "",
            },
            sanitized: false,
          };
        },
      }),
    };

    interface Held {
      /** Resolves once the `count`th call waits in the seam. */
      entered: (count?: number) => Promise<undefined>;
      release: () => void;
    }

    /**
     * `context`'s seam replaced: each call waits until `release`. An injector's
     * stand-in then writes its success row through the logger the injector was
     * built with, the first `rowsOnEntry` calls on arrival instead.
     */
    function holdSeam(context: string, rowsOnEntry = 0): Held {
      const gate = deferred<undefined>();
      const arrivals = [deferred<undefined>(), deferred<undefined>()];
      const logger = at().auditLogger;
      let calls = 0;
      const hold = async (row: () => void): Promise<void> => {
        const call = calls++;
        if (call < rowsOnEntry) row();
        arrivals[call]?.resolve(undefined);
        await gate.promise;
        if (call >= rowsOnEntry) row();
      };
      const position = ATTRIBUTION_AT[context];
      if (position === undefined) {
        const install = ENGINE_AUDITED[context] as (answer: () => Promise<unknown>) => object;
        Object.assign(
          engine,
          install(() => hold(() => undefined)),
        );
      } else {
        Object.assign(engine, {
          [`${context}Injector`]: {
            executeWithSecret: async (...args: unknown[]) => {
              await hold(() => {
                logger.log(
                  withAttribution(
                    {
                      eventType: AuditEventType.SECRET_USE,
                      secretId,
                      detail: { context, status: 200 },
                      success: true,
                    },
                    args[position] as AuditAttribution | undefined,
                  ),
                );
              });
              return { type: context };
            },
          },
        });
      }
      return {
        entered: (count = 1) => (arrivals[count - 1] as { promise: Promise<undefined> }).promise,
        release: () => gate.resolve(undefined),
      };
    }

    function useRows(id: string): { success: boolean; detail: Record<string, unknown> | null }[] {
      return engine
        .queryAudit({ eventType: AuditEventType.SECRET_USE, secretId: id })
        .map((row) => ({ success: row.success, detail: row.detail }));
    }

    it.each(CONTEXTS)(
      "a wipe during a $context use: the caller reads VAULT_LOCKED and the trail has one row",
      async ({ context, action }) => {
        const held = holdSeam(context);
        const values = retainDecryptedValues(engine);
        const pending = quiet(engine.useSecret(HANDLE, action, ALICE));
        await Promise.race([held.entered(), pending]);

        sealExpired();
        held.release();

        await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
        await engine.unlock("password");
        expect(useRows(secretId)).toStrictEqual([
          {
            success: false,
            detail: { handle: HANDLE, context, error: ErrorCode.VAULT_LOCKED, interface: "rest" },
          },
        ]);
        expect(values.length).toBe(1);
        expect(values.every(allZero)).toBe(true);
      },
    );

    it("a wipe between an injector's row and the engine's return writes no second row", async () => {
      const held = holdSeam("http", 1);
      const pending = use();
      await Promise.race([held.entered(), pending]);

      sealExpired();
      held.release();

      expect(await pending).toStrictEqual({ type: "http" });
      await engine.unlock("password");
      expect(useRows(secretId)).toStrictEqual([STUB_ROW]);
    });

    it("a wipe in the wait of the terminate after the value block's refusal writes no second row", async () => {
      vi.spyOn(at().secretManager, "getSecretValue").mockRejectedValue(
        VaultError.secretRevoked(HANDLE),
      );
      wipeDuring(registryOf(engine), "terminate", async () => sealExpired());

      await expectVaultError(() => use(), ErrorCode.SECRET_REVOKED);

      await engine.unlock("password");
      expect(useRows(secretId)).toStrictEqual([
        {
          success: false,
          detail: {
            handle: HANDLE,
            context: "http",
            error: ErrorCode.SECRET_REVOKED,
            interface: "rest",
          },
        },
      ]);
    });

    it.each([
      {
        first: "has no row yet",
        rowsOnEntry: 0,
        firstRow: lockedRow("rest"),
        settle: (first: Promise<unknown>) => expectVaultError(() => first, ErrorCode.VAULT_LOCKED),
      },
      {
        first: "has written its row",
        rowsOnEntry: 1,
        firstRow: STUB_ROW,
        settle: async (first: Promise<unknown>) =>
          expect(await first).toStrictEqual({ type: "http" }),
      },
    ])(
      "two uses of one secret open at a wipe get a row each — the first $first",
      async ({ rowsOnEntry, firstRow, settle }) => {
        const held = holdSeam("http", rowsOnEntry);
        const first = quiet(use());
        await Promise.race([held.entered(1), first]);
        const second = quiet(engine.useSecret(HANDLE, HTTP, { ...ALICE, interface: "mcp" }));
        await Promise.race([held.entered(2), second]);

        sealExpired();
        held.release();

        await settle(first);
        await expectVaultError(() => second, ErrorCode.VAULT_LOCKED);
        await engine.unlock("password");
        expect(useRows(secretId)).toStrictEqual([lockedRow("mcp"), firstRow]);
      },
    );

    it("a lock and then a destroy write one row for an open use", async () => {
      const held = holdSeam("http");
      const pending = quiet(use());
      await Promise.race([held.entered(), pending]);

      await engine.lock();
      await engine.destroy();
      held.release();

      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      await engine.unlock("password");
      expect(useRows(secretId)).toStrictEqual([lockedRow("rest")]);
    });

    it("a seal row that cannot be written leaves the keys zero", async () => {
      const held = holdSeam("http");
      const pending = quiet(use());
      await Promise.race([held.entered(), pending]);
      const kek = at().kek as Uint8Array;
      vi.spyOn(at().store, "insertAuditEvent").mockImplementation(() => {
        throw new Error("audit unavailable");
      });

      sealExpired();

      expect(allZero(kek)).toBe(true);
      held.release();
      await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
      await engine.unlock("password");
      expect(useRows(secretId)).toStrictEqual([]);
    });

    it("a use that ends inside lock()'s window returns its result", async () => {
      const closing = deferred<undefined>();
      const closeGate = deferred<undefined>();
      await seedLiveStdioEntry(engine, secretId, () => {
        closing.resolve(undefined);
        return closeGate.promise;
      });
      const held = holdSeam("http");
      const pending = use();
      await Promise.race([held.entered(), pending]);
      const locking = engine.lock();
      await closing.promise;

      held.release();

      expect(await pending).toStrictEqual({ type: "http" });
      closeGate.resolve(undefined);
      await locking;
      await engine.unlock("password");
      expect(useRows(secretId)).toStrictEqual([STUB_ROW]);
    });

    it("a wipe after a proxy's decrypt and before its lease", async () => {
      const values = retainDecryptedValues(engine);
      wipeDuring(at().secretManager, "getSecretValue", async () => sealExpired());
      const lease = vi.spyOn(
        engine as unknown as { openProxyLease: () => unknown },
        "openProxyLease",
      );

      await expectVaultError(() => proxy(), ErrorCode.VAULT_LOCKED);

      expect(lease).not.toHaveBeenCalled();
      expect(values.length).toBe(1);
      expect(values.every(allZero)).toBe(true);
      await engine.unlock("password");
      expect(useRows(secretId)).toStrictEqual([
        {
          success: false,
          detail: {
            context: "proxy",
            method: "GET",
            origin: "https://api.example.com",
            path: "/x",
            error: ErrorCode.VAULT_LOCKED,
            interface: "proxy",
          },
        },
      ]);
    });

    it("a wipe during a signature's decrypt", async () => {
      await listKeys();
      const values = retainDecryptedValues(engine);
      wipeDuring(at().secretManager, "getSecretValue", async () => sealExpired());

      await expectVaultError(sign, ErrorCode.VAULT_LOCKED);

      expect(values.length).toBe(1);
      expect(values.every(allZero)).toBe(true);
      await engine.unlock("password");
      expect(useRows(await engine.resolveSecretId("secret://deploy-ed"))).toStrictEqual([
        {
          success: false,
          detail: {
            context: "ssh_agent",
            key_type: "ssh-ed25519",
            error: ErrorCode.VAULT_LOCKED,
            interface: "ssh_agent",
          },
        },
      ]);
    });

    it("a use without a caller keeps its rows byte-identical", async () => {
      const server = createServer((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end("{}");
      });
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      try {
        const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        await engine.setInjectionPolicy(HANDLE, { url_allowlist: [`${origin}/*`] });

        await engine.useSecret(HANDLE, {
          type: "http",
          method: "GET",
          url: `${origin}/status`,
          injection: { type: "bearer" },
        });

        const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_USE, secretId });
        expect(
          rows.map((row) => [row.principal_type, row.principal_id, row.ip_address, row.success]),
        ).toStrictEqual([[null, null, null, true]]);
        expect(rows[0]?.detail).toStrictEqual({
          context: "http",
          method: "GET",
          url: `${origin}/status`,
          status: 200,
          injection_type: "bearer",
          response_mode: "filtered",
        });
      } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });

    async function wipeAtLookup(lookup: "url" | "host"): Promise<void> {
      const real = await vi.importActual<typeof import("./injection/url-validator.js")>(
        "./injection/url-validator.js",
      );
      if (lookup === "url") {
        vi.mocked(validateUrl).mockImplementationOnce(async (...args) => {
          const answer = await real.validateUrl(...args);
          sealExpired();
          return answer;
        });
      } else {
        vi.mocked(validateHostPort).mockImplementationOnce(async (...args) => {
          const answer = await real.validateHostPort(...args);
          sealExpired();
          return answer;
        });
      }
    }

    const SENDS: {
      use: string;
      context: string;
      lookup: "url" | "host";
      target: (port: number) => {
        policy: Parameters<VaultEngine["setInjectionPolicy"]>[1];
        action: UseSecretAction;
      };
    }[] = [
      {
        use: "an http",
        context: "http",
        lookup: "url",
        target: (port) => ({
          policy: { url_allowlist: [`http://127.0.0.1:${port}/*`] },
          action: {
            type: "http",
            method: "GET",
            url: `http://127.0.0.1:${port}/x`,
            injection: { type: "bearer" },
          },
        }),
      },
      {
        use: "a websocket",
        context: "websocket",
        lookup: "url",
        target: (port) => ({
          policy: { url_allowlist: [`ws://127.0.0.1:${port}/*`] },
          action: {
            type: "websocket",
            url: `ws://127.0.0.1:${port}/feed`,
            injection: { type: "bearer" },
          },
        }),
      },
      {
        use: "a database",
        context: "database",
        lookup: "host",
        target: (port) => ({
          policy: { host_allowlist: [`127.0.0.1:${port}`] },
          action: {
            type: "database",
            engine: "postgresql",
            host: "127.0.0.1",
            port,
            database: "app",
            query: "SELECT 1",
          },
        }),
      },
      {
        use: "an smtp",
        context: "smtp",
        lookup: "host",
        target: (port) => ({
          policy: { host_allowlist: [`127.0.0.1:${port}`] },
          action: {
            type: "smtp",
            host: "127.0.0.1",
            port,
            security: "tls",
            from: "ops@example.com",
            to: ["dev@example.com"],
            subject: "build finished",
            text: "green",
          },
        }),
      },
      {
        use: "an imap",
        context: "imap",
        lookup: "host",
        target: (port) => ({
          policy: { host_allowlist: [`127.0.0.1:${port}`] },
          action: {
            type: "imap",
            host: "127.0.0.1",
            port,
            mailbox: "INBOX",
            operation: { kind: "search", unseen: true },
          },
        }),
      },
    ];

    it.each(SENDS.map((send) => [send.use, send] as const))(
      "a wipe before %s use sends: nothing is sent, one row",
      async (_use, { context, lookup, target }) => {
        let connections = 0;
        const server = createTcpServer((socket) => {
          connections += 1;
          socket.destroy();
        });
        await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
        try {
          const { policy, action } = target((server.address() as AddressInfo).port);
          const id = await addSecret("pair", `svc:${randomBytes(12).toString("base64url")}`);
          grantUse(id, "alice");
          await engine.setInjectionPolicy(PAIR, policy);
          await wipeAtLookup(lookup);

          await expectVaultError(
            () => engine.useSecret(PAIR, action, ALICE),
            ErrorCode.VAULT_LOCKED,
          );

          expect(connections).toBe(0);
          await engine.unlock("password");
          expect(useRows(id)).toStrictEqual([
            {
              success: false,
              detail: { handle: PAIR, context, error: ErrorCode.VAULT_LOCKED, interface: "rest" },
            },
          ]);
        } finally {
          await new Promise<void>((resolve) => server.close(() => resolve()));
        }
      },
    );

    describe("an MCP use", () => {
      let mcpId: string;
      /** Every downstream child a row has seen begin its handshake. */
      let children: number[] = [];

      const mcpUse = (): Promise<unknown> =>
        engine.useSecret(MCP, { type: "mcp", server: "test-mcp", tool: "leak" }, ALICE);

      /** Records each child as its handshake begins; with `hold`, that first message waits for `release`. */
      function watchHandshakes(hold: boolean): { begun: Promise<number>; release: () => void } {
        const begun = deferred<number>();
        const gate = deferred<undefined>();
        const send = StdioChildTransport.prototype.send;
        vi.spyOn(StdioChildTransport.prototype, "send").mockImplementation(async function (
          this: StdioChildTransport,
          message,
        ) {
          if ((message as { method?: unknown }).method === "initialize") {
            children.push(this.pid as number);
            begun.resolve(this.pid as number);
            if (hold) await gate.promise;
          }
          return send.call(this, message);
        });
        return { begun: begun.promise, release: () => gate.resolve(undefined) };
      }

      /** A seeded live entry whose close holds `lock()` in its wait until `open`. */
      async function holdLock(): Promise<{ closing: Promise<undefined>; open: () => void }> {
        const closing = deferred<undefined>();
        const closeGate = deferred<undefined>();
        await seedLiveStdioEntry(engine, secretId, () => {
          closing.resolve(undefined);
          return closeGate.promise;
        });
        return { closing: closing.promise, open: () => closeGate.resolve(undefined) };
      }

      beforeEach(async () => {
        mcpId = await addSecret("mcp", randomBytes(18).toString("base64url"));
        grantUse(mcpId, "alice");
        await engine.setInjectionPolicy(
          MCP,
          { command_allowlist: [process.execPath] },
          { acknowledge_interpreters: true },
        );
        await engine.setMcpServerConfig(MCP, {
          server_name: "test-mcp",
          transport: "stdio",
          protocol: "2025-11-25",
          command: process.execPath,
          args: ["-e", MCP_TEST_SERVER],
          env_var: "DOWNSTREAM_TOKEN",
        });
      });

      afterEach(() => {
        for (const pid of children.filter(isAlive)) {
          try {
            process.kill(pid, "SIGKILL");
          } catch {
            // Gone meanwhile.
          }
        }
        children = [];
      });

      it("an MCP use in flight under lock() reads MCP_CONNECT_FAILED with its own row", async () => {
        const held = await holdLock();
        const handshakes = watchHandshakes(true);
        const pending = quiet(mcpUse());
        await Promise.race([handshakes.begun, pending]);
        const locking = engine.lock();
        await held.closing;

        handshakes.release();

        await expectVaultError(() => pending, ErrorCode.MCP_CONNECT_FAILED);
        held.open();
        await locking;
        await engine.unlock("password");
        expect(useRows(mcpId)).toStrictEqual([
          {
            success: false,
            detail: {
              context: "mcp",
              server: "test-mcp",
              tool: "leak",
              transport: "stdio",
              error: ErrorCode.MCP_CONNECT_FAILED,
              interface: "rest",
            },
          },
        ]);
      });

      it("an MCP use in flight under a session expiry reads VAULT_LOCKED, one row, the child gone", async () => {
        const handshakes = watchHandshakes(true);
        const pending = quiet(mcpUse());
        const pid = await Promise.race([handshakes.begun, pending]);

        sealExpired();

        await vi.waitFor(() => expect(isAlive(pid as number)).toBe(false), {
          timeout: GONE_TIMEOUT_MS,
          interval: 50,
        });
        handshakes.release();
        await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
        await engine.unlock("password");
        expect(useRows(mcpId)).toStrictEqual([
          {
            success: false,
            detail: {
              handle: MCP,
              context: "mcp",
              error: ErrorCode.VAULT_LOCKED,
              interface: "rest",
            },
          },
        ]);
      });

      it("an MCP use that starts inside lock()'s wait starts no child", async () => {
        const held = await holdLock();
        watchHandshakes(false);
        let locking: Promise<void> = Promise.resolve();
        wipeDuring(at().secretManager, "getSecretValue", async () => {
          locking = engine.lock();
          await held.closing;
        });

        await expectVaultError(mcpUse, ErrorCode.VAULT_LOCKED);

        held.open();
        await locking;
        expect(children).toStrictEqual([]);
        await engine.unlock("password");
        expect(useRows(mcpId)).toStrictEqual([
          {
            success: false,
            detail: {
              context: "mcp",
              server: "test-mcp",
              tool: "leak",
              transport: "stdio",
              error: ErrorCode.VAULT_LOCKED,
              interface: "rest",
            },
          },
        ]);
        expect(useRows(secretId)).toStrictEqual([]);
      });
    });
  });
});

describe("an OAuth use under a wipe", () => {
  const ctx = useOAuthEngine();

  afterEach(async () => {
    await ctx.engine.unlock("password");
    expect(ctx.engine.verifyAuditChain().valid).toBe(true);
  });

  /** An OAuth secret whose access token is still valid, inside the 60 s refresh window. */
  async function oauthSecret(): Promise<string> {
    const config: OAuthProviderConfig = {
      provider: "github",
      grant_type: "authorization_code",
      token_endpoint: ctx.tokenEndpoint,
      auth_endpoint: "https://github.com/login/oauth/authorize",
      client_id: "operator-cid",
      client_secret: CLIENT_SECRET,
    };
    const { secretId } = await ctx.engine.createOAuthSecret("gh", config);
    await ctx.engine.completeOAuthFlow(secretId, ACCESS_TOKEN, REFRESH_TOKEN, Date.now() + 30_000);
    await ctx.engine.setInjectionPolicy("secret://gh", {
      url_allowlist: ["https://api.example.com/*"],
    });
    return secretId;
  }

  /** The engine's HTTP injector replaced: records the token each use hands it. */
  function stubHttpInjector(): string[] {
    const handed: string[] = [];
    (ctx.engine as unknown as EngineInternals).httpInjector = {
      executeWithSecret: (...args: unknown[]) => {
        handed.push(Buffer.from(args[1] as Uint8Array).toString("utf8"));
        return Promise.resolve({ type: "http", status: 200 });
      },
    };
    return handed;
  }

  /** The token endpoint's answer held until `release`; `arrived` once the request is in. */
  function holdTokenRequest(): { arrived: Promise<void>; release: () => void } {
    let release: () => void = () => undefined;
    ctx.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const arrived = new Promise<void>((resolve) => {
      ctx.onRequest = resolve;
    });
    return { arrived, release: () => release() };
  }

  function useOAuth(): Promise<unknown> {
    return ctx.engine.useSecret("secret://gh", {
      type: "http",
      method: "GET",
      url: "https://api.example.com/user",
      injection: { type: "bearer" },
    });
  }

  function tokenColumns(secretId: string): unknown {
    return readRow(
      ctx.dbPath,
      "SELECT access_token_encrypted, refresh_token_encrypted, access_token_expires_at FROM oauth_tokens WHERE secret_id = ?",
      secretId,
    );
  }

  it.each([
    {
      how: "a lock and an unlock",
      reunlock: async (): Promise<void> => {
        await ctx.engine.lock();
        await ctx.engine.unlock("password");
      },
    },
    { how: "an unlock over the live engine", reunlock: () => ctx.engine.unlock("password") },
  ])("an OAuth use that outlives $how reads no key of the new session", async ({ reunlock }) => {
    const handed = stubHttpInjector();
    await oauthSecret();
    const held = holdTokenRequest();
    const pending = quiet(useOAuth());
    await Promise.race([held.arrived, pending]);

    await reunlock();
    const count = nonReadAuditCount(ctx.engine);
    held.release();

    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
    expect(handed.length).toBe(0);
    expect(nonReadAuditCount(ctx.engine)).toBe(count);
  });

  it.each([
    { wipe: "lock()", run: (): Promise<void> => ctx.engine.lock() },
    {
      wipe: "sealExpired()",
      run: (): Promise<void> => {
        (ctx.engine as unknown as EngineInternals).sealExpired();
        return Promise.resolve();
      },
    },
  ])("a wipe under an OAuth refresh changes no token row — $wipe", async ({ run }) => {
    const handed = stubHttpInjector();
    const secretId = await oauthSecret();
    const before = tokenColumns(secretId);
    const held = holdTokenRequest();
    const pending = quiet(useOAuth());
    await Promise.race([held.arrived, pending]);

    await run();
    held.release();

    await expectVaultError(() => pending, ErrorCode.VAULT_LOCKED);
    expect(handed.length).toBe(0);
    await ctx.engine.unlock("password");
    expect(tokenColumns(secretId)).toEqual(before);
  });

  it("a refresh that ends inside lock()'s window is stored", async () => {
    const handed = stubHttpInjector();
    const secretId = await oauthSecret();
    const closing = deferred<undefined>();
    const closeGate = deferred<undefined>();
    await seedLiveStdioEntry(ctx.engine, secretId, () => {
      closing.resolve(undefined);
      return closeGate.promise;
    });
    const before = tokenColumns(secretId);
    const held = holdTokenRequest();
    const pending = quiet(useOAuth());
    await Promise.race([held.arrived, pending]);
    const locking = ctx.engine.lock();
    await closing.promise;

    held.release();

    await pending;
    closeGate.resolve(undefined);
    await locking;
    expect(tokenColumns(secretId)).not.toEqual(before);
    await ctx.engine.unlock("password");
    const after = stubHttpInjector();
    await useOAuth();
    expect(ctx.requests.length).toBe(1);
    expect([handed.length, after.length]).toStrictEqual([1, 1]);
    expect(handed[0] === RENEWED && after[0] === RENEWED).toBe(true);
  });
});
