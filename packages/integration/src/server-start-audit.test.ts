import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMcpServer } from "@harpoc/mcp-server";
import { AuditEventType, ErrorCode, SecretType } from "@harpoc/shared";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { callTool, parseToolResult } from "./helpers/mcp-helpers.js";

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

  it("records the token-gate refusal as a failed row carrying the code", () => {
    expect(() => createMcpServer({ engine: vault.engine })).toThrow(
      expect.objectContaining({ code: ErrorCode.TOKEN_REQUIRED }),
    );

    const rows = vault.engine.queryAudit({ eventType: AuditEventType.SERVER_START });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail?.error).toBe(ErrorCode.TOKEN_REQUIRED);
    expect(rows[0]?.detail?.tokenless).toBe(false);

    const report = vault.engine.verifyAuditChain();
    expect(report.valid).toBe(true);
  });

  it("a token-bearing start writes tokenless: false with the subject, unattributed (R4/B22)", () => {
    const token = vault.engine.createToken("agent-1", ["read", "list", "use"]);

    createMcpServer({ engine: vault.engine, launchToken: token });

    const rows = vault.engine.queryAudit({
      eventType: AuditEventType.SERVER_START,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toMatchObject({
      transport: "stdio",
      tokenless: false,
      subject: "agent-1",
    });
    expect(rows[0]?.principal_type).toBeNull();
    expect(stderrWrites.join("")).not.toContain("WARNING");
  });

  it("a tokenless server attributes its rows to tokenless-stdio (R4/E78b)", async () => {
    await vault.engine.createSecret({
      name: "tl-key",
      type: SecretType.API_KEY,
      value: new Uint8Array(Buffer.from("v")),
    });
    const server = createMcpServer({
      engine: vault.engine,
      allowTokenless: true,
    });
    try {
      parseToolResult(
        await callTool(server, "get_secret_info", { handle: "secret://tl-key" }),
        "get_secret_info",
      );
    } finally {
      await server.close();
    }

    const row = vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_READ })
      .find((r) => r.success);
    expect(row?.principal_type).toBe("user");
    expect(row?.principal_id).toBe("tokenless-stdio");
    expect(row?.detail?.interface).toBe("mcp");
    // The waiver row itself stays unattributed — it takes no caller.
    const start = vault.engine.queryAudit({
      eventType: AuditEventType.SERVER_START,
    })[0];
    expect(start?.principal_type).toBeNull();
  });
});
