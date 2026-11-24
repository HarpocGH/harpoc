import { randomBytes } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext, UseSecretAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretStatus } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { registerAgents, registryOf, seedLiveStdioEntry } from "./__fixtures__/engine-seams.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const HANDLE = "secret://pw";
const MARK_AT = 1_700_000_000_000;
const HTTP = {
  type: "http",
  method: "GET",
  url: "https://api.example.com/",
} as unknown as UseSecretAction;
const UNCONFIRMED =
  "SSH bootstrap unconfirmed: a bootstrap of this secret has no confirmed outcome, so the secret was ended; a key and a sudoers drop-in may be installed on the host";
const IN_FLIGHT = "SSH bootstrap in flight: another bootstrap of this secret is running";

let tempDir: string;
let dbPath: string;
let engine: VaultEngine;
let second: VaultEngine | undefined;
let password: string;
let secretId: string;

interface EngineInternals {
  secretManager: { getSecretValue: (handle: string) => Promise<Uint8Array> };
  store: SqliteStore;
  bootstrapHolds: Map<string, string>;
}

function internals(of: VaultEngine = engine): EngineInternals {
  return of as unknown as EngineInternals;
}

function store(): SqliteStore {
  return internals().store;
}

function rowsOf(eventType: AuditEventType) {
  return engine.queryAudit({ eventType, secretId });
}

function failAuditInsert(nth: number): void {
  const live = store();
  const insert = live.insertAuditEvent.bind(live);
  let calls = 0;
  vi.spyOn(live, "insertAuditEvent").mockImplementation(
    (...args: Parameters<SqliteStore["insertAuditEvent"]>) => {
      calls += 1;
      if (calls === nth) throw new Error("audit unavailable");
      return insert(...args);
    },
  );
}

async function expectEnded(at: VaultEngine, caller?: CallerContext): Promise<void> {
  const err = await expectVaultError(
    () => at.useSecret(HANDLE, HTTP, caller),
    ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
  );
  expect(err.message).toBe(UNCONFIRMED);
}

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-bootstrap-mark-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  engine = new VaultEngine({ dbPath, sessionPath: join(tempDir, "session.json") });
  password = randomBytes(18).toString("base64url");
  await engine.initVault("password");
  await engine.createSecret({
    name: "pw",
    type: "api_key",
    value: new Uint8Array(Buffer.from(password)),
  });
  secretId = await engine.resolveSecretId(HANDLE);
});

afterEach(async () => {
  vi.restoreAllMocks();
  try {
    await second?.destroy();
  } finally {
    second = undefined;
    await engine.destroy();
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

describe("useSecret — a bootstrap mark nobody holds ends the secret", () => {
  it("a mark nobody holds ends the secret at its next use, before the decrypt", async () => {
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, HTTP),
      ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
    );
    expectAbsent(err.message, password);
    expect(err.message).toBe(UNCONFIRMED);
    expect(getSecretValue).not.toHaveBeenCalled();

    const uses = rowsOf(AuditEventType.SECRET_USE);
    expect(uses).toHaveLength(1);
    expect(uses[0]?.success).toBe(false);
    expect(uses[0]?.detail).toStrictEqual({
      handle: HANDLE,
      context: "http",
      error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      secret_ended: true,
      mark_at: MARK_AT,
    });
    const revokes = rowsOf(AuditEventType.SECRET_REVOKE);
    expect(revokes).toHaveLength(1);
    expect(revokes[0]?.success).toBe(true);
    expect(revokes[0]?.detail).toStrictEqual({ handle: HANDLE, reason: "ssh_bootstrap" });
    expect(store().getSecret(secretId)?.status).toBe(SecretStatus.REVOKED);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();

    await expectVaultError(() => engine.useSecret(HANDLE, HTTP), ErrorCode.SECRET_REVOKED);
    expect(getSecretValue).not.toHaveBeenCalled();
    expect(rowsOf(AuditEventType.SECRET_REVOKE)).toHaveLength(1);
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("it asks no revoke grant and names who used the secret", async () => {
    registerAgents(engine, "alice");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alice", permissions: ["use"] },
      "test-admin",
    );
    const alice: CallerContext = {
      principal_type: "agent",
      principal_id: "alice",
      interface: "rest",
    };
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);

    await expectEnded(engine, alice);

    const [use] = rowsOf(AuditEventType.SECRET_USE);
    expect(use).toMatchObject({ success: false, principal_type: "agent", principal_id: "alice" });
    expect(use?.detail).toStrictEqual({
      handle: HANDLE,
      context: "http",
      error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      secret_ended: true,
      mark_at: MARK_AT,
      interface: "rest",
    });
    const revokes = rowsOf(AuditEventType.SECRET_REVOKE);
    expect(revokes).toHaveLength(1);
    expect(revokes[0]).toMatchObject({
      success: true,
      principal_type: "agent",
      principal_id: "alice",
    });
    expect(revokes[0]?.detail).toStrictEqual({
      handle: HANDLE,
      reason: "ssh_bootstrap",
      interface: "rest",
    });
    expect(store().getSecret(secretId)?.status).toBe(SecretStatus.REVOKED);
  });

  it.each([
    { failing: "the revoke row", nth: 1 },
    { failing: "the use row", nth: 2 },
  ])("the ending commits whole or not at all — $failing cannot be written", async ({ nth }) => {
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);
    failAuditInsert(nth);

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, HTTP),
      ErrorCode.INTERNAL_ERROR,
    );
    expect(err.message).toBe("the use failed unexpectedly");
    vi.restoreAllMocks();

    expect(store().getSecret(secretId)?.status).toBe(SecretStatus.ACTIVE);
    expect(store().readBootstrapMark(secretId)).toEqual({ claim: "claim-other", at: MARK_AT });
    expect(rowsOf(AuditEventType.SECRET_REVOKE)).toHaveLength(0);
    expect(rowsOf(AuditEventType.SECRET_USE).map((row) => row.detail)).toStrictEqual([
      { handle: HANDLE, context: "http", error: ErrorCode.INTERNAL_ERROR },
    ]);

    await expectEnded(engine);
    expect(store().getSecret(secretId)?.status).toBe(SecretStatus.REVOKED);
    expect(rowsOf(AuditEventType.SECRET_REVOKE)).toHaveLength(1);
    expect(store().readBootstrapMark(secretId)).toBeUndefined();
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("it ends the secret's live child as a revocation does", async () => {
    await seedLiveStdioEntry(engine, secretId);
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);

    await expectEnded(engine);

    expect(registryOf(engine).get(secretId)).toBeUndefined();
    const terminates = rowsOf(AuditEventType.MCP_TERMINATE);
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail).toMatchObject({ reason: "secret_revoked", server: "docs" });
  });

  it("the status answers first", async () => {
    await engine.revokeSecret(HANDLE);
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);

    await expectVaultError(() => engine.useSecret(HANDLE, HTTP), ErrorCode.SECRET_REVOKED);

    expect(store().readBootstrapMark(secretId)).toEqual({ claim: "claim-other", at: MARK_AT });
    expect(rowsOf(AuditEventType.SECRET_USE).map((row) => row.detail)).toStrictEqual([
      { handle: HANDLE, context: "http", error: ErrorCode.SECRET_REVOKED },
    ]);
    expect(rowsOf(AuditEventType.SECRET_REVOKE)).toHaveLength(1);
  });
});

describe("useSecret — a bootstrap mark this engine holds", () => {
  it("a mark this engine's running call holds refuses in flight and changes nothing", async () => {
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);
    internals().bootstrapHolds.set(secretId, "claim-other");
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");

    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, HTTP),
      ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
    );
    expectAbsent(err.message, password);
    expect(err.message).toBe(IN_FLIGHT);
    expect(getSecretValue).not.toHaveBeenCalled();

    const uses = rowsOf(AuditEventType.SECRET_USE);
    expect(uses).toHaveLength(1);
    expect(uses[0]?.success).toBe(false);
    expect(uses[0]?.detail).toStrictEqual({
      handle: HANDLE,
      context: "http",
      error: ErrorCode.SSH_BOOTSTRAP_IN_FLIGHT,
    });
    expect(store().getSecret(secretId)?.status).toBe(SecretStatus.ACTIVE);
    expect(store().readBootstrapMark(secretId)).toEqual({ claim: "claim-other", at: MARK_AT });
    expect(rowsOf(AuditEventType.SECRET_REVOKE)).toHaveLength(0);
  });

  it("a lock gives the hold up, and the rows of the ending are the new unlock's", async () => {
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);
    internals().bootstrapHolds.set(secretId, "claim-other");

    await engine.lock();
    await engine.unlock("password");
    await expectEnded(engine);

    const uses = rowsOf(AuditEventType.SECRET_USE);
    expect(uses).toHaveLength(1);
    expect(uses[0]?.detail_unreadable).toBe(false);
    expect(uses[0]?.detail).toStrictEqual({
      handle: HANDLE,
      context: "http",
      error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
      secret_ended: true,
      mark_at: MARK_AT,
    });
    const revokes = rowsOf(AuditEventType.SECRET_REVOKE);
    expect(revokes).toHaveLength(1);
    expect(revokes[0]?.detail_unreadable).toBe(false);
    expect(revokes[0]?.detail).toStrictEqual({ handle: HANDLE, reason: "ssh_bootstrap" });
    expect(engine.verifyAuditChain().valid).toBe(true);
  });

  it("a second engine on the vault ends the secret under the first's hold", async () => {
    store().claimBootstrapMark(secretId, "claim-other", MARK_AT);
    internals().bootstrapHolds.set(secretId, "claim-other");
    second = new VaultEngine({ dbPath, sessionPath: join(tempDir, "other-session.json") });
    await second.unlock("password");

    await expectEnded(second);

    const uses = rowsOf(AuditEventType.SECRET_USE);
    expect(uses.map((row) => row.detail)).toStrictEqual([
      {
        handle: HANDLE,
        context: "http",
        error: ErrorCode.SSH_BOOTSTRAP_UNCONFIRMED,
        secret_ended: true,
        mark_at: MARK_AT,
      },
    ]);
    expect(rowsOf(AuditEventType.SECRET_REVOKE).map((row) => row.detail)).toStrictEqual([
      { handle: HANDLE, reason: "ssh_bootstrap" },
    ]);
    expect(internals(second).store.readBootstrapMark(secretId)).toBeUndefined();

    await expectVaultError(() => engine.useSecret(HANDLE, HTTP), ErrorCode.SECRET_REVOKED);
  });
});
