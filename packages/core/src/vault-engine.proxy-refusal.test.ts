import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import {
  AuditEventType,
  auditScopeFromToken,
  callerFromToken,
  ErrorCode,
  SecretType,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { nonReadAuditCount, registerAgents } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

const CONNECT = "CONNECT evil.example:443";

let tempDir: string;
let engine: VaultEngine;
let caller: CallerContext;

beforeEach(async () => {
  tempDir = join(
    tmpdir(),
    `harpoc-proxy-refusal-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  registerAgents(engine, "agent-a");
  caller = callerFromToken(
    engine.verifyToken(engine.createToken("agent-a", ["use"])),
    "proxy",
    "127.0.0.1",
  );
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function deniedRows() {
  return engine.queryAudit({ eventType: AuditEventType.ACCESS_DENIED });
}

describe("VaultEngine.auditProxyRefusal — the egress proxy's access.denied row", () => {
  it("writes one access.denied row with the code, the operation and the proxy reason", () => {
    engine.auditProxyRefusal(caller, CONNECT, ErrorCode.PROXY_CONNECT_DENIED);

    const rows = deniedRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      secret_id: null,
      principal_type: "agent",
      principal_id: "agent-a",
      ip_address: "127.0.0.1",
      success: false,
    });
    expect(rows[0]?.detail).toEqual({
      operation: CONNECT,
      error: "PROXY_CONNECT_DENIED",
      reason: "proxy",
      interface: "proxy",
    });
  });

  it("cuts an operation at 300 characters", () => {
    const operation = `CONNECT ${"a".repeat(5_000)}:443`;
    engine.auditProxyRefusal(caller, operation, ErrorCode.PROXY_CONNECT_DENIED);

    const rows = deniedRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail?.operation).toHaveLength(300);
    expect(rows[0]?.detail?.operation).toBe(operation.slice(0, 300));
  });

  it("a sealed engine refuses VAULT_LOCKED and writes nothing", async () => {
    const before = nonReadAuditCount(engine);
    await engine.lock();

    await expectVaultError(
      () => engine.auditProxyRefusal(caller, CONNECT, ErrorCode.PROXY_CONNECT_DENIED),
      ErrorCode.VAULT_LOCKED,
    );

    await engine.unlock("password");
    expect(deniedRows()).toHaveLength(0);
    expect(nonReadAuditCount(engine)).toBe(before + 2);
  });

  it("a scoped reader does not see the row", async () => {
    await engine.createSecret({
      name: "billing",
      type: SecretType.API_KEY,
      project: "finance",
      value: new Uint8Array(Buffer.from("v")),
    });
    registerAgents(engine, "finance-reader");
    const reader = engine.verifyToken(
      engine.createToken("finance-reader", ["admin"], undefined, { project: "finance" }),
    );
    engine.auditProxyRefusal(caller, CONNECT, ErrorCode.PROXY_CONNECT_DENIED);

    expect(
      engine.queryAudit(
        { eventType: AuditEventType.ACCESS_DENIED },
        auditScopeFromToken(reader),
        callerFromToken(reader, "rest"),
      ),
    ).toEqual([]);
    expect(deniedRows()).toHaveLength(1);
  });

  it("leaves auditScopeRefusal's row as it is", () => {
    engine.auditProxyRefusal(caller, CONNECT, ErrorCode.PROXY_CONNECT_DENIED);
    engine.auditScopeRefusal(caller, "GET https://api.example.com", "permission");

    expect(deniedRows().map((row) => row.detail)).toEqual([
      {
        operation: "GET https://api.example.com",
        error: "ACCESS_DENIED",
        reason: "permission",
        interface: "proxy",
      },
      {
        operation: CONNECT,
        error: "PROXY_CONNECT_DENIED",
        reason: "proxy",
        interface: "proxy",
      },
    ]);
  });

  it("the chain verifies", () => {
    engine.auditProxyRefusal(caller, CONNECT, ErrorCode.PROXY_CONNECT_DENIED);
    engine.auditProxyRefusal(caller, "GET https://10.0.0.1", ErrorCode.SSRF_BLOCKED);
    engine.auditProxyRefusal(caller, "proxy refusal budget", ErrorCode.RATE_LIMIT_EXCEEDED);

    expect(deniedRows()).toHaveLength(3);
    expect(engine.verifyAuditChain().valid).toBe(true);
  });
});
