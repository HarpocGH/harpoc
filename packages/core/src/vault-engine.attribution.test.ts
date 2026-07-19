import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

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
let engine: VaultEngine;

const NODE = process.execPath;
const VALUE = new Uint8Array(Buffer.from("attr-engine-secret", "utf8"));

const REST_CALLER: CallerContext = {
  principal_type: "agent",
  principal_id: "alice",
  interface: "rest",
};

beforeEach(async () => {
  tempDir = join(tmpdir(), `harpoc-attr-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

async function makeProcessSecret(name: string): Promise<void> {
  await engine.createSecret({ name, type: SecretType.API_KEY, value: new Uint8Array(VALUE) });
  await engine.setInjectionPolicy(
    `secret://${name}`,
    { url_allowlist: [], command_allowlist: [NODE], env_allowlist: [] },
    { acknowledge_interpreters: true },
  );
}

const PROCESS_ACTION = {
  type: "process",
  command: NODE,
  args: ["-e", "process.exit(0)"],
  env_var: "SECRET",
} as const;

describe("use_secret success-row attribution (V2 end-to-end)", () => {
  it("a caller-attributed use stamps principal, session and interface on the injector-written success row", async () => {
    await makeProcessSecret("attr-proc");
    await engine.useSecret("secret://attr-proc", PROCESS_ACTION, REST_CALLER);

    const uses = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(uses).toHaveLength(1);
    const row = uses[0];
    expect(row?.success).toBe(true);
    expect(row?.principal_type).toBe("agent");
    expect(row?.principal_id).toBe("alice");
    expect(row?.session_id).toEqual(expect.any(String));
    expect(row?.detail?.interface).toBe("rest");
    expect(row?.detail?.context).toBe("process");
  });

  it("a trusted-local use keeps NULL principal columns and no interface, but carries the session (D4 pin)", async () => {
    await makeProcessSecret("local-proc");
    await engine.useSecret("secret://local-proc", PROCESS_ACTION);

    const uses = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(uses).toHaveLength(1);
    const row = uses[0];
    expect(row?.success).toBe(true);
    expect(row?.principal_type).toBeNull();
    expect(row?.principal_id).toBeNull();
    expect(row?.session_id).toEqual(expect.any(String));
    expect(row?.detail && "interface" in (row.detail as object)).toBe(false);
  });

  it("the audit chain stays green over attributed rows", async () => {
    await makeProcessSecret("chain-proc");
    await engine.useSecret("secret://chain-proc", PROCESS_ACTION, REST_CALLER);
    await engine.useSecret("secret://chain-proc", PROCESS_ACTION);

    const report = engine.verifyAuditChain();
    expect(report.firstBrokenId).toBeNull();
    expect(report.valid).toBe(true);
  });
});

describe("engine-row interface stamping", () => {
  it("read success rows carry detail.interface for an interface-tagged caller", async () => {
    await makeProcessSecret("attr-read");
    await engine.getSecretValue("secret://attr-read", REST_CALLER);

    const reads = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    const row = reads.find((e) => e.detail?.action === "get_value");
    expect(row?.principal_id).toBe("alice");
    expect(row?.detail?.interface).toBe("rest");
  });

  it("denial rows (auditDenied path) carry detail.interface", async () => {
    await expect(
      engine.getSecretValue("secret://does-not-exist", REST_CALLER),
    ).rejects.toMatchObject({ code: ErrorCode.SECRET_NOT_FOUND });

    const reads = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    const denial = reads.find((e) => e.success === false);
    expect(denial?.principal_id).toBe("alice");
    expect(denial?.detail?.error).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(denial?.detail?.interface).toBe("rest");
  });

  it("policy-denial rows carry detail.interface beside required_permission", async () => {
    await makeProcessSecret("attr-gated");
    const secretId = await engine.resolveSecretId("secret://attr-gated");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "someone-else", permissions: ["use"] },
      "test-admin",
    );

    await expect(
      engine.useSecret("secret://attr-gated", PROCESS_ACTION, REST_CALLER),
    ).rejects.toMatchObject({ code: ErrorCode.ACCESS_DENIED });

    const uses = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const denial = uses.find((e) => e.success === false);
    expect(denial?.principal_id).toBe("alice");
    expect(denial?.detail?.required_permission).toBe("use");
    expect(denial?.detail?.interface).toBe("rest");
  });
});

describe("interface is never load-bearing for policy matching (D3 pin)", () => {
  it("grant and deny outcomes are identical with and without the interface tag", async () => {
    await makeProcessSecret("iface-neutral");
    const secretId = await engine.resolveSecretId("secret://iface-neutral");
    engine.grantPolicy(
      { secretId, principalType: "agent", principalId: "alice", permissions: ["use"] },
      "test-admin",
    );

    const alicePlain: CallerContext = { principal_type: "agent", principal_id: "alice" };
    const bobTagged: CallerContext = {
      principal_type: "agent",
      principal_id: "bob",
      interface: "mcp-http",
    };
    const bobPlain: CallerContext = { principal_type: "agent", principal_id: "bob" };

    await expect(
      engine.useSecret("secret://iface-neutral", PROCESS_ACTION, REST_CALLER),
    ).resolves.toBeDefined();
    await expect(
      engine.useSecret("secret://iface-neutral", PROCESS_ACTION, alicePlain),
    ).resolves.toBeDefined();
    await expect(
      engine.useSecret("secret://iface-neutral", PROCESS_ACTION, bobTagged),
    ).rejects.toMatchObject({ code: ErrorCode.ACCESS_DENIED });
    await expect(
      engine.useSecret("secret://iface-neutral", PROCESS_ACTION, bobPlain),
    ).rejects.toMatchObject({ code: ErrorCode.ACCESS_DENIED });
  });
});
