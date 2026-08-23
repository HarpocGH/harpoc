import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMcpServer } from "@harpoc/mcp-server";
import { AuditEventType } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const PASSWORD = "integration-password";

let vault: TestVault;
let stderrWrites: string[];
let restoreStderr: (() => void) | null = null;

beforeEach(async () => {
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  registerAgents(vault.engine, "agent-1");

  // The tokenless branch writes its warning to the real stderr; capture it so
  // the suite output stays readable and the ordering stays assertable.
  stderrWrites = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array): boolean => {
    stderrWrites.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  restoreStderr = () => {
    process.stderr.write = original;
  };
});

afterEach(async () => {
  restoreStderr?.();
  restoreStderr = null;
  await destroyTestVault(vault);
});

// W6: the --allow-tokenless waiver belongs in the tamper-evident trail, not
// only on a log pipe. These walk the real engine and the real createMcpServer
// choke point against a real database file.

describe("tokenless MCP server start lands in the audit trail", () => {
  it("records the waiver, unattributed, with the chain still verifiable", () => {
    const server = createMcpServer({ engine: vault.engine, allowTokenless: true });
    expect(server).toBeDefined();
    expect(stderrWrites.join("")).toContain("WARNING");

    const rows = vault.engine.queryAudit({ eventType: AuditEventType.SERVER_START });
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row?.success).toBe(true);
    expect(row?.detail?.tokenless).toBe(true);
    expect(row?.detail?.transport).toBe("stdio");
    // No requesting principal exists for a console-launched server.
    expect(row?.principal_type).toBeNull();
    expect(row?.principal_id).toBeNull();
    expect(row?.session_id).toEqual(expect.any(String));

    const report = vault.engine.verifyAuditChain();
    expect(report.valid).toBe(true);
    expect(report.firstBrokenId).toBeNull();
  });

  it("an anchor taken before the start still verifies afterwards", () => {
    const anchor = vault.engine.getAuditChainTail();
    expect(anchor).not.toBeNull();

    createMcpServer({ engine: vault.engine, allowTokenless: true });

    const report = vault.engine.verifyAuditChain({ anchor: anchor ?? undefined });
    expect(report.valid).toBe(true);
    expect(report.anchor?.status).toBe("ok");
  });

  it("a token-bearing start writes no row (D2)", () => {
    const token = vault.engine.createToken("agent-1", ["read", "list", "use"]);

    createMcpServer({ engine: vault.engine, launchToken: token });

    expect(vault.engine.queryAudit({ eventType: AuditEventType.SERVER_START })).toHaveLength(0);
    expect(stderrWrites.join("")).not.toContain("WARNING");
  });
});
