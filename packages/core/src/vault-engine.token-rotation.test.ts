import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { DecryptedAuditEvent } from "./audit/audit-query.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";
import { registerAgents } from "./__fixtures__/engine-seams.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine;

function liveStore(): SqliteStore {
  return (engine as unknown as { store: SqliteStore }).store;
}

function tokenRows(success: boolean): DecryptedAuditEvent[] {
  return engine.queryAudit({ eventType: AuditEventType.TOKEN_CREATE, success });
}

function jtiOf(token: string): string {
  const payload = token.split(".")[1] ?? "";
  return (JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { jti: string }).jti;
}

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-rot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  registerAgents(engine, "bot");
});

afterEach(async () => {
  vi.restoreAllMocks();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("createToken without the rotation option (model A unchanged)", () => {
  it("writes the token.create row with subject, jti, scope and principal_type alone — no rotation key", () => {
    const token = engine.createToken("bot", ["use"], 60_000);

    const [row] = tokenRows(true);
    expect(Object.keys(row?.detail ?? {})).toEqual(["subject", "jti", "scope", "principal_type"]);
    expect(row?.detail).toEqual({
      subject: "bot",
      jti: jtiOf(token),
      scope: ["use"],
      principal_type: "agent",
    });
  });

  it("refuses a deactivated agent AGENT_INACTIVE and writes no row", async () => {
    engine.deactivateAgent("bot");

    await expectVaultError(() => engine.createToken("bot", ["use"]), ErrorCode.AGENT_INACTIVE);
    expect(engine.queryAudit({ eventType: AuditEventType.TOKEN_CREATE })).toHaveLength(0);
  });
});

describe("createToken with the rotation option (deployment model B, M2)", () => {
  it("mints and adds rotation: true to the token.create row beside the model-A keys", () => {
    const token = engine.createToken("bot", ["use"], 60_000, {
      secrets: ["db-*"],
      label: "rotation",
      rotation: {},
    });

    expect(engine.verifyToken(token).sub).toBe("bot");
    const [row] = tokenRows(true);
    expect(row?.detail).toEqual({
      subject: "bot",
      jti: jtiOf(token),
      scope: ["use"],
      principal_type: "agent",
      label: "rotation",
      rotation: true,
    });
  });

  it("re-mints over a live previous jti and leaves the previous token valid", () => {
    const first = engine.createToken("bot", ["use"], 60_000, { rotation: {} });
    const second = engine.createToken("bot", ["use"], 60_000, {
      rotation: { previousJti: jtiOf(first) },
    });

    expect(jtiOf(second)).not.toBe(jtiOf(first));
    expect(engine.verifyToken(first).jti).toBe(jtiOf(first));
    expect(tokenRows(true)).toHaveLength(2);
  });

  it("refuses a revoked previous jti TOKEN_REVOKED after a failed token.create row, minting nothing", async () => {
    const first = engine.createToken("bot", ["use"], 60_000, { rotation: {} });
    engine.revokeToken(jtiOf(first));

    await expectVaultError(
      () => engine.createToken("bot", ["use"], 60_000, { rotation: { previousJti: jtiOf(first) } }),
      ErrorCode.TOKEN_REVOKED,
    );

    const [failed] = tokenRows(false);
    expect(failed?.detail).toEqual({
      subject: "bot",
      principal_type: "agent",
      rotation: true,
      error: "TOKEN_REVOKED",
    });
    expect(failed?.principal_id).toBeNull();
    expect(tokenRows(true)).toHaveLength(1);
    expect(liveStore().listIssuedTokens()).toHaveLength(1);
  });

  it("refuses a deactivated agent AGENT_INACTIVE after a failed token.create row", async () => {
    engine.deactivateAgent("bot");

    await expectVaultError(
      () => engine.createToken("bot", ["use"], 60_000, { rotation: {} }),
      ErrorCode.AGENT_INACTIVE,
    );

    expect(tokenRows(false).map((row) => row.detail)).toEqual([
      { subject: "bot", principal_type: "agent", rotation: true, error: "AGENT_INACTIVE" },
    ]);
    expect(liveStore().listIssuedTokens()).toHaveLength(0);
  });

  it("refuses an unregistered agent AGENT_NOT_FOUND after a failed token.create row", async () => {
    await expectVaultError(
      () => engine.createToken("ghost", ["use"], 60_000, { rotation: {} }),
      ErrorCode.AGENT_NOT_FOUND,
    );

    expect(tokenRows(false).map((row) => row.detail)).toEqual([
      { subject: "ghost", principal_type: "agent", rotation: true, error: "AGENT_NOT_FOUND" },
    ]);
  });

  it("judges the registry before the revocation: a deactivation that revoked the previous token reads AGENT_INACTIVE", async () => {
    const first = engine.createToken("bot", ["use"], 60_000, { rotation: {} });
    engine.deactivateAgent("bot");
    expect(engine.isTokenRevoked(jtiOf(first))).toBe(true);

    await expectVaultError(
      () => engine.createToken("bot", ["use"], 60_000, { rotation: { previousJti: jtiOf(first) } }),
      ErrorCode.AGENT_INACTIVE,
    );
    expect(tokenRows(false).map((row) => row.detail?.error)).toEqual(["AGENT_INACTIVE"]);
  });

  it("still refuses a revoked previous jti after its denylist entry was pruned at expiry (the registry's revoked_at mirror)", async () => {
    const first = engine.createToken("bot", ["use"], 60_000, { rotation: {} });
    engine.revokeToken(jtiOf(first));
    const afterExpiry = Date.now() + 120_000;
    vi.spyOn(Date, "now").mockReturnValueOnce(afterExpiry);
    expect(liveStore().pruneExpiredTokens()).toBe(1);
    expect(engine.isTokenRevoked(jtiOf(first))).toBe(false);

    await expectVaultError(
      () => engine.createToken("bot", ["use"], 60_000, { rotation: { previousJti: jtiOf(first) } }),
      ErrorCode.TOKEN_REVOKED,
    );
  });
});
