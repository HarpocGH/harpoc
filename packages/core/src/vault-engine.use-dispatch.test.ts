import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import { forceNetworkIsolationUnavailableForTests } from "./injection/network-isolation.js";

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
});
