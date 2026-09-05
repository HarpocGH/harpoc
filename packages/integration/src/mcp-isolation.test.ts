import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { requireFsIsolation, requireNetworkIsolation } from "@harpoc/core";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { assertTierAvailable } from "./helpers/platform-tiers.js";

/**
 * Stdio MCP downstreams under an isolation policy (thesis §4.5.3 layer 4,
 * compromise audit D51): the child is spawned through the same wrappers as the
 * process contexts instead of being refused. The real-kernel proof: the
 * downstream answers through the wrapper, the spawn row names the mechanism,
 * the credential still never reaches the caller, and the vault's lock takes
 * the payload down THROUGH the wrapper — pinned on the payload's OWN pid,
 * which under bwrap is not the pid the vault holds (the monitor's), so this is
 * the kill-chain proof for that tier. The fixture holds a timer and never
 * exits on stdin EOF, so the close must escalate to a signal — the chain under
 * test. Attempt-and-skip on the live probes; Windows refuses by design (pinned
 * in mcp-context.test.ts).
 */

const PASSWORD = "integration-test-pw";
const SECRET = "sk-mcp-iso-secret-0f1e2d3c4b";
const NODE = process.execPath;
const MECHANISMS = ["unshare", "landlock", "sandbox-exec", "bwrap"];

const DOWNSTREAM_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
setInterval(() => {}, 60000);
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "integ-isolated-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    const name = m.params.name;
    if (name === "pid") {
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: String(process.pid) }] } });
    } else if (name === "leak-env") {
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: process.env.TOKEN || "unset" }] } });
    } else {
      send({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Unknown tool" } });
    }
  }
});
`;

function mcpAction(tool: string) {
  return { type: "mcp" as const, server: "integ-iso-mcp", tool };
}

async function setupVault(policy: {
  network_isolation?: boolean;
  fs_isolation?: boolean;
}): Promise<{ vault: TestVault; handle: string }> {
  const vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
  const created = await vault.engine.createSecret({
    name: "mcp-iso-key",
    type: "api_key",
    value: new Uint8Array(Buffer.from(SECRET, "utf8")),
  });
  await vault.engine.setInjectionPolicy(
    created.handle,
    { url_allowlist: [], command_allowlist: [NODE], env_allowlist: [], ...policy },
    { acknowledge_interpreters: true },
  );
  await vault.engine.setMcpServerConfig(created.handle, {
    server_name: "integ-iso-mcp",
    transport: "stdio",
    command: NODE,
    args: ["-e", DOWNSTREAM_SERVER],
    env_var: "TOKEN",
  });
  return { vault, handle: created.handle };
}

function textOf(result: unknown): string {
  const content = (result as { content?: { text?: string }[] }).content ?? [];
  return content.map((c) => c.text ?? "").join("");
}

async function pollDead(pid: number): Promise<void> {
  await expect
    .poll(
      () => {
        try {
          process.kill(pid, 0);
          return "alive";
        } catch {
          return "dead";
        }
      },
      { timeout: 10_000 },
    )
    .toBe("dead");
}

const posix = process.platform === "linux" || process.platform === "darwin";

describe.skipIf(!posix)("stdio MCP downstream under network_isolation — real kernel", () => {
  let available = false;
  let vault: TestVault | undefined;

  beforeAll(async () => {
    let probeError: unknown;
    try {
      await requireNetworkIsolation("/bin/true", []);
      available = true;
    } catch (err) {
      probeError = err;
    }
    assertTierAvailable("isolation", available, probeError);
  });

  afterEach(async () => {
    if (vault) {
      await destroyTestVault(vault);
      vault = undefined;
    }
  });

  it("spawns the downstream through the wrapper, names the mechanism on mcp.spawn, and still redacts the credential", async (ctx) => {
    if (!available) return ctx.skip();
    const setup = await setupVault({ network_isolation: true });
    vault = setup.vault;
    const pid = await vault.engine.useSecret(setup.handle, mcpAction("pid"));
    expect(pid.type).toBe("mcp");
    expect(Number(textOf(pid))).toBeGreaterThan(0);

    const spawns = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    expect(spawns).toHaveLength(1);
    expect(spawns[0]?.detail?.command).toBe(NODE);
    expect(MECHANISMS).toContain(spawns[0]?.detail?.isolation_mechanism);
    expect("fs_isolation_mechanism" in (spawns[0]?.detail ?? {})).toBe(false);

    const leak = await vault.engine.useSecret(setup.handle, mcpAction("leak-env"));
    expect(JSON.stringify(leak)).not.toContain(SECRET);
    expect(JSON.stringify(leak)).toContain("[REDACTED]");
  });

  it("lock() takes the payload down through the wrapper — the payload's own pid, not only the vault's handle on the wrapper, and under bwrap the two differ (the monitor and its payload)", async (ctx) => {
    if (!available) return ctx.skip();
    const setup = await setupVault({ network_isolation: true });
    vault = setup.vault;
    const payloadPid = Number(textOf(await vault.engine.useSecret(setup.handle, mcpAction("pid"))));
    const spawn = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN })[0];
    const wrapperPid = spawn?.detail?.pid as number;
    expect(payloadPid).toBeGreaterThan(0);
    expect(wrapperPid).toBeGreaterThan(0);
    if (spawn?.detail?.isolation_mechanism === "bwrap") {
      expect(payloadPid).not.toBe(wrapperPid);
    }

    await vault.engine.lock();

    await pollDead(wrapperPid);
    await pollDead(payloadPid);
    await vault.engine.unlock(PASSWORD);
    const terminates = vault.engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("vault_lock");
  });
});

describe.skipIf(!posix)("stdio MCP downstream under fs_isolation — real kernel", () => {
  let available = false;
  let vault: TestVault | undefined;

  beforeAll(async () => {
    let probeError: unknown;
    try {
      await requireFsIsolation("/bin/true", []);
      available = true;
    } catch (err) {
      probeError = err;
    }
    assertTierAvailable("fs-isolation", available, probeError);
  });

  afterEach(async () => {
    if (vault) {
      await destroyTestVault(vault);
      vault = undefined;
    }
  });

  it("spawns the downstream through the write-denying wrapper and names the mechanism", async (ctx) => {
    if (!available) return ctx.skip();
    const setup = await setupVault({ fs_isolation: true });
    vault = setup.vault;
    const pid = await vault.engine.useSecret(setup.handle, mcpAction("pid"));
    expect(Number(textOf(pid))).toBeGreaterThan(0);
    const spawns = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    expect(MECHANISMS).toContain(spawns[0]?.detail?.fs_isolation_mechanism);
    expect("isolation_mechanism" in (spawns[0]?.detail ?? {})).toBe(false);
  });

  it("names both mechanisms when both flags are demanded", async (ctx) => {
    if (!available) return ctx.skip();
    let bothAvailable = true;
    try {
      await requireNetworkIsolation("/bin/true", []);
    } catch {
      bothAvailable = false;
    }
    if (!bothAvailable) return ctx.skip();
    const setup = await setupVault({ network_isolation: true, fs_isolation: true });
    vault = setup.vault;
    await vault.engine.useSecret(setup.handle, mcpAction("pid"));
    const spawns = vault.engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    expect(MECHANISMS).toContain(spawns[0]?.detail?.isolation_mechanism);
    expect(MECHANISMS).toContain(spawns[0]?.detail?.fs_isolation_mechanism);
  });
});
