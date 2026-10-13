import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode, MAX_PROCESS_OUTPUT_BYTES, VaultState } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { forceNetworkIsolationUnavailableForTests } from "./injection/network-isolation.js";
import { registryOf } from "./__fixtures__/engine-seams.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("useSecret (process injection)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "proc",
      type: "api_key",
      value: new Uint8Array(Buffer.from("procsecret")),
    });
  });

  it("runs an allowlisted command with the secret injected as an env var", async () => {
    await engine.setInjectionPolicy(
      "secret://proc",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    const res = await engine.useSecret("secret://proc", {
      type: "process",
      command: process.execPath,
      args: ["-e", `process.stdout.write(process.env.TOKEN ? "SET" : "UNSET")`],
      env_var: "TOKEN",
    });
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.exit_code).toBe(0);
    expect(res.stdout).toBe("SET");
  });

  it("redacts the secret from process output", async () => {
    await engine.setInjectionPolicy(
      "secret://proc",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    const res = await engine.useSecret("secret://proc", {
      type: "process",
      command: process.execPath,
      args: ["-e", `process.stdout.write(process.env.TOKEN)`],
      env_var: "TOKEN",
    });
    if (res.type !== "process") throw new Error("expected process result");
    expect(res.stdout).not.toContain("procsecret");
    expect(res.stdout).toContain("[REDACTED]");
  });

  it("denies a process command by default when no allowlist is set", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://proc", {
          type: "process",
          command: process.execPath,
          args: ["-e", `process.stdout.write("x")`],
          env_var: "TOKEN",
        }),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });

  it("refuses fail-closed when policy demands isolation the platform cannot deliver", async () => {
    forceNetworkIsolationUnavailableForTests("forced for test");
    try {
      await engine.setInjectionPolicy(
        "secret://proc",
        { command_allowlist: [process.execPath], network_isolation: true },
        { acknowledge_interpreters: true },
      );
      await expect(
        engine.useSecret("secret://proc", {
          type: "process",
          command: process.execPath,
          args: ["-e", `process.stdout.write("ran")`],
          env_var: "TOKEN",
        }),
      ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });

      // The refusal is audited with the error code — no silent degrade,
      // no invisible denial (the M8 posture).
      const useEvents = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
      expect(useEvents.some((e) => e.detail?.error === "NETWORK_ISOLATION_UNAVAILABLE")).toBe(true);
    } finally {
      forceNetworkIsolationUnavailableForTests(null);
    }
  });

  it("control: the same use without the isolation flag executes", async () => {
    forceNetworkIsolationUnavailableForTests("forced for test");
    try {
      await engine.setInjectionPolicy(
        "secret://proc",
        { command_allowlist: [process.execPath] },
        { acknowledge_interpreters: true },
      );
      const res = await engine.useSecret("secret://proc", {
        type: "process",
        command: process.execPath,
        args: ["-e", `process.stdout.write("ran")`],
        env_var: "TOKEN",
      });
      if (res.type !== "process") throw new Error("expected process result");
      expect(res.exit_code).toBe(0);
      expect(res.stdout).toBe("ran");
    } finally {
      forceNetworkIsolationUnavailableForTests(null);
    }
  });

  // M-P2-22 (test-review-2026-10-09): the process context's secondary behaviours
  // through the engine — env passthrough, stderr, the exit code, the output cap.
  async function allowNode(envAllowlist: string[] = []): Promise<void> {
    await engine.setInjectionPolicy(
      "secret://proc",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: envAllowlist },
      { acknowledge_interpreters: true },
    );
  }

  async function runNode(script: string): Promise<{
    stdout: string;
    stderr: string;
    exit_code: number | null;
    truncated?: boolean;
    error?: string;
  }> {
    const res = await engine.useSecret("secret://proc", {
      type: "process",
      command: process.execPath,
      args: ["-e", script],
      env_var: "TOKEN",
    });
    if (res.type !== "process") throw new Error("expected process result");
    return res;
  }

  function processRow(): { success: boolean; detail: Record<string, unknown> | null } {
    const rows = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(rows).toHaveLength(1);
    return { success: rows[0]?.success as boolean, detail: rows[0]?.detail ?? null };
  }

  it("passes an allowlisted variable through to the child and no other (M-P2-22)", async () => {
    vi.stubEnv("HARPOC_P222_ALLOWED", "p222-allowed");
    vi.stubEnv("HARPOC_P222_OTHER", "p222-other");
    try {
      await allowNode(["HARPOC_P222_ALLOWED"]);
      const res = await runNode(
        "process.stdout.write(JSON.stringify([process.env.HARPOC_P222_ALLOWED ?? null, process.env.HARPOC_P222_OTHER ?? null]))",
      );

      expect(JSON.parse(res.stdout)).toEqual(["p222-allowed", null]);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("captures stderr apart from stdout, redacted (M-P2-22)", async () => {
    await allowNode();
    const res = await runNode(
      'process.stdout.write("out"); process.stderr.write("err:" + process.env.TOKEN)',
    );

    expect(res.stdout).toBe("out");
    expect(res.stderr).toBe("err:[REDACTED]");
    expect(processRow()).toMatchObject({
      success: true,
      detail: { context: "process", exit_code: 0, sanitized: true },
    });
  });

  it("maps a non-zero exit onto the result's exit_code and the row's detail (M-P2-22)", async () => {
    await allowNode();
    const res = await runNode("process.exit(3)");

    expect(res.exit_code).toBe(3);
    expect(res.error).toBeUndefined();
    expect(processRow()).toMatchObject({
      success: true,
      detail: { context: "process", exit_code: 3, timed_out: false },
    });
  });

  it("keeps the first MAX_PROCESS_OUTPUT_BYTES of each stream and drops the rest (M-P2-22)", async () => {
    await allowNode();
    const res = await runNode(
      `const over = "HEAD" + "a".repeat(${MAX_PROCESS_OUTPUT_BYTES + 262_144}) + "TAIL";` +
        "process.stdout.write(over); process.stderr.write(over);",
    );

    for (const out of [res.stdout, res.stderr]) {
      expect(Buffer.byteLength(out)).toBe(MAX_PROCESS_OUTPUT_BYTES);
      expect(out.slice(0, 4)).toBe("HEAD");
      expect(out.slice(-4)).toBe("aaaa");
    }
    expect(res.truncated).toBe(true);
    expect(processRow()).toMatchObject({ success: true, detail: { truncated: true } });
  });
});

describe("useSecret (database) — engine dispatch", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "db",
      type: "api_key",
      value: new Uint8Array(Buffer.from("admin:dbpass")),
    });
  });

  it("rejects a host outside the host allowlist before connecting", async () => {
    await engine.setInjectionPolicy("secret://db", {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["db.internal:5432"],
    });
    await expectVaultError(
      () =>
        engine.useSecret("secret://db", {
          type: "database",
          engine: "postgresql",
          host: "8.8.8.8",
          database: "app",
          query: "SELECT 1",
        }),
      ErrorCode.HOST_NOT_ALLOWED,
    );
    const denied = engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .find((e) => e.detail?.error === "HOST_NOT_ALLOWED");
    expect(denied?.success).toBe(false);
    expect(denied?.detail?.context).toBe("database");
  });

  it("blocks SSRF to a private database host", async () => {
    await engine.setInjectionPolicy("secret://db", { host_allowlist: ["10.0.0.5"] });
    await expectVaultError(
      () =>
        engine.useSecret("secret://db", {
          type: "database",
          engine: "postgresql",
          host: "10.0.0.5",
          database: "app",
          query: "SELECT 1",
        }),
      ErrorCode.SSRF_BLOCKED,
    );
  });
});

describe("useSecret (ssh) — engine dispatch", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "sshkey",
      type: "api_key",
      value: new Uint8Array(
        Buffer.from("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----"),
      ),
    });
  });

  it("denies by default when the host allowlist is empty", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://sshkey", {
          type: "ssh",
          host: "deploy.example.com",
          user: "deploy",
          command: "whoami",
        }),
      ErrorCode.HOST_NOT_ALLOWED,
    );
  });

  it("requires pinned host keys once the host is allowlisted", async () => {
    await engine.setInjectionPolicy("secret://sshkey", {
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: ["deploy.example.com"],
    });
    await expectVaultError(
      () =>
        engine.useSecret("secret://sshkey", {
          type: "ssh",
          host: "deploy.example.com",
          user: "deploy",
          command: "whoami",
        }),
      ErrorCode.SSH_NOT_CONFIGURED,
    );
  });
});

describe("useSecret (git) — engine dispatch", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "gh",
      type: "api_key",
      value: new Uint8Array(Buffer.from("x-access-token:ghp_token")),
    });
  });

  it("rejects a forbidden transport before touching the command", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://gh", {
          type: "git",
          operation: "clone",
          repository: "ext::sh -c whoami",
        }),
      ErrorCode.GIT_UNSUPPORTED_TRANSPORT,
    );
  });

  it("denies git by default when no command allowlist is set", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://gh", {
          type: "git",
          operation: "clone",
          repository: "https://github.com/user/repo.git",
        }),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });
});

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

describe("useSecret (MCP proxy)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "mcpuse",
      type: "api_key",
      value: new Uint8Array(Buffer.from("mcpusesecret")),
    });
  });

  it("rejects an mcp action when no server config is set", async () => {
    await expectVaultError(
      () =>
        engine.useSecret("secret://mcpuse", {
          type: "mcp",
          server: "github-mcp",
          tool: "echo",
        }),
      ErrorCode.MCP_SERVER_NOT_CONFIGURED,
    );
  });

  it("forwards a tool call to a spawned stdio server with the credential injected", async () => {
    await engine.setInjectionPolicy(
      "secret://mcpuse",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      protocol: "2025-11-25",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });

    const res = await engine.useSecret("secret://mcpuse", {
      type: "mcp",
      server: "test-mcp",
      tool: "leak",
    });
    if (res.type !== "mcp") throw new Error("expected mcp result");
    // The downstream server echoed its env credential; the vault redacted it.
    const text = JSON.stringify(res.content);
    expect(text).not.toContain("mcpusesecret");
    expect(text).toContain("[REDACTED]");
  });

  it("fail-safe denies a stdio launch without a command allowlist", async () => {
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      protocol: "2025-11-25",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });
    await expectVaultError(
      () =>
        engine.useSecret("secret://mcpuse", {
          type: "mcp",
          server: "test-mcp",
          tool: "leak",
        }),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });

  it("audits mcp.spawn on first use and secret.use with context=mcp", async () => {
    await engine.setInjectionPolicy(
      "secret://mcpuse",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      protocol: "2025-11-25",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });

    await engine.useSecret("secret://mcpuse", { type: "mcp", server: "test-mcp", tool: "leak" });
    await engine.useSecret("secret://mcpuse", { type: "mcp", server: "test-mcp", tool: "leak" });

    const spawns = engine.queryAudit({ eventType: AuditEventType.MCP_SPAWN });
    expect(spawns).toHaveLength(1);
    expect(spawns[0]?.detail?.server).toBe("test-mcp");

    const uses = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    const mcpUses = uses.filter((e) => e.detail?.context === "mcp");
    expect(mcpUses).toHaveLength(2);
  });

  it("lock() terminates live downstream servers and audits mcp.terminate", async () => {
    await engine.setInjectionPolicy(
      "secret://mcpuse",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      protocol: "2025-11-25",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });
    await engine.useSecret("secret://mcpuse", { type: "mcp", server: "test-mcp", tool: "leak" });

    await engine.lock();

    // The terminate must have been audited before the keys were wiped.
    await engine.unlock("password");
    const terminates = engine.queryAudit({ eventType: AuditEventType.MCP_TERMINATE });
    expect(terminates).toHaveLength(1);
    expect(terminates[0]?.detail?.reason).toBe("vault_lock");
  });

  // M-P2-23 (test-review-2026-10-09): the downstream teardown on the seal paths
  // beside lock — destroy, the monitor's expiry seal and the lazy expiry seal.
  async function spawnLiveDownstream(): Promise<number> {
    await engine.setInjectionPolicy(
      "secret://mcpuse",
      { url_allowlist: [], command_allowlist: [process.execPath], env_allowlist: [] },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      protocol: "2025-11-25",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
    });
    await engine.useSecret("secret://mcpuse", { type: "mcp", server: "test-mcp", tool: "leak" });
    const secretId = await engine.resolveSecretId("secret://mcpuse");
    const pid = registryOf(engine).get(secretId)?.stdioTransport?.pid;
    if (pid === undefined) throw new Error("expected a live stdio downstream child");
    expect(isAlive(pid)).toBe(true);
    return pid;
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

  function terminateReasons(): unknown[] {
    return engine
      .queryAudit({ eventType: AuditEventType.MCP_TERMINATE })
      .map((row) => row.detail?.reason);
  }

  it("destroy() terminates live downstream servers and audits mcp.terminate", async () => {
    const pid = await spawnLiveDownstream();

    await engine.destroy();

    await vi.waitFor(() => expect(isAlive(pid)).toBe(false));
    await engine.unlock("password");
    expect(terminateReasons()).toEqual(["engine_destroy"]);
  });

  it("the monitor's expiry seal terminates live downstream servers and audits mcp.terminate", async () => {
    const pid = await spawnLiveDownstream();
    const session = JSON.parse(readFileSync(sessionPath, "utf-8")) as Record<string, unknown>;
    session.expires_at = Date.now() - 1;
    writeFileSync(sessionPath, JSON.stringify(session));

    await (engine as unknown as { sessionMonitorTick(): Promise<void> }).sessionMonitorTick();

    expect(engine.getState()).toBe(VaultState.SEALED);
    await vi.waitFor(() => expect(isAlive(pid)).toBe(false));
    await engine.unlock("password");
    expect(terminateReasons()).toEqual(["session_expired"]);
  });

  it("the lazy expiry seal kills live downstream servers and writes no mcp.terminate row (the synchronous seal)", async () => {
    const pid = await spawnLiveDownstream();
    (engine as unknown as { sessionExpiresAt: number }).sessionExpiresAt = Date.now() - 1;

    await expectVaultError(() => engine.listSecrets(), ErrorCode.VAULT_LOCKED);

    expect(engine.getState()).toBe(VaultState.SEALED);
    await vi.waitFor(() => expect(isAlive(pid)).toBe(false));
    await engine.unlock("password");
    expect(terminateReasons()).toEqual([]);
  });

  // I17 (test-review-2026-10-09): replacing or deleting the downstream config
  // terminates the live connection (api-reference "the next invocation
  // connects with the new config" — the injector's respawn is
  // mcp-injector.test.ts "terminates and respawns when the config changes").
  it("a changed server config terminates the live downstream child and audits config_changed (I17)", async () => {
    const pid = await spawnLiveDownstream();
    const secretId = await engine.resolveSecretId("secret://mcpuse");

    await engine.setMcpServerConfig("secret://mcpuse", {
      server_name: "test-mcp",
      transport: "stdio",
      protocol: "2025-11-25",
      command: process.execPath,
      args: ["-e", MCP_TEST_SERVER],
      env_var: "DOWNSTREAM_TOKEN",
      working_directory: tempDir,
    });

    await vi.waitFor(() => expect(isAlive(pid)).toBe(false));
    expect(registryOf(engine).get(secretId)).toBeUndefined();
    expect(terminateReasons()).toEqual(["config_changed"]);
  });

  it("a deleted server config terminates the live downstream child and audits config_removed (I17)", async () => {
    const pid = await spawnLiveDownstream();
    const secretId = await engine.resolveSecretId("secret://mcpuse");

    await expect(engine.deleteMcpServerConfig("secret://mcpuse")).resolves.toBe(true);

    await vi.waitFor(() => expect(isAlive(pid)).toBe(false));
    expect(registryOf(engine).get(secretId)).toBeUndefined();
    expect(terminateReasons()).toEqual(["config_removed"]);
  });
});
